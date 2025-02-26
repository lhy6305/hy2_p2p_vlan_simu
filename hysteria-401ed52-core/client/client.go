package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/intl/congestion"
	"github.com/apernet/hysteria/core/v2/intl/protocol"
	"github.com/apernet/hysteria/core/v2/intl/utils"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client interface {
	TCP(addr string) (net.Conn, error)
	UDP() (HyUDPConn, error)
	Close() error
}

type HyUDPConn interface {
	Receive() ([]byte, string, error)
	Send([]byte, string) error
	Close() error
}

type HandshakeInfo struct {
	UDPEnabled bool
	Tx         uint64 // 0 if using BBR
}

func NewClient(config *Config) (*ClientImpl, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	c := &ClientImpl{
		Config:       config,
		AuthFinished: false,
	}
	return c, nil
}

type ClientImpl struct {
	Config *Config

	PktConn net.PacketConn
	Conn    quic.Connection

	Authenticated     bool
	AuthFinished      bool
	AuthFinishedMutex sync.Mutex

	udpSM *udpSessionManager
}

func (c *ClientImpl) Connect() (*HandshakeInfo, error) {
	pktConn, err := c.Config.ConnFactory.New(c.Config.ServerAddr)
	if err != nil {
		return nil, err
	}
	// Convert config to TLS config & QUIC config
	tlsConfig := &tls.Config{
		ServerName:            c.Config.TLSConfig.ServerName,
		InsecureSkipVerify:    c.Config.TLSConfig.InsecureSkipVerify,
		VerifyPeerCertificate: c.Config.TLSConfig.VerifyPeerCertificate,
		RootCAs:               c.Config.TLSConfig.RootCAs,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     c.Config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.Config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.Config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.Config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.Config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                c.Config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.Config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
	// Prepare RoundTripper
	var conn quic.EarlyConnection
	rt := &http3.RoundTripper{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, pktConn, c.Config.ServerAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	// Send auth HTTP request
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: c.Config.Auth,
		Rx:   c.Config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req) // will block if server failed to response
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		c.AuthFinishedMutex.Lock()
		if !c.AuthFinished {
			c.Authenticated = false
			c.AuthFinished = true
		}
		c.AuthFinishedMutex.Unlock()
		return nil, coreErrs.ConnectError{Err: err}
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = pktConn.Close()
		c.AuthFinishedMutex.Lock()
		if !c.AuthFinished {
			c.Authenticated = false
			c.AuthFinished = true
		}
		c.AuthFinishedMutex.Unlock()
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}

	// Auth OK
	c.AuthFinishedMutex.Lock()
	if !c.AuthFinished {
		c.Authenticated = true
		c.AuthFinished = true
	}
	c.AuthFinishedMutex.Unlock()

	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use BBR
		congestion.UseBBR(conn)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.Config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.Config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(conn, actualTx)
		} else {
			// We don't know our own bandwidth either, use BBR
			congestion.UseBBR(conn)
		}
	}
	_ = resp.Body.Close()

	c.PktConn = pktConn
	c.Conn = conn
	if authResp.UDPEnabled {
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn})
	}
	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

// OpenStream wraps the stream with QStream, which handles Close() properly
func (c *ClientImpl) OpenStream() (quic.Stream, error) {
	stream, err := c.Conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *ClientImpl) TCP(addr string) (net.Conn, error) {
	stream, err := c.OpenStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if c.Config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  c.Conn.LocalAddr(),
			PseudoRemoteAddr: c.Conn.RemoteAddr(),
			Established:      false,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  c.Conn.LocalAddr(),
		PseudoRemoteAddr: c.Conn.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *ClientImpl) UDP() (HyUDPConn, error) {
	if c.udpSM == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	return c.udpSM.NewUDP()
}

func (c *ClientImpl) Close() error {
	if c.Conn != nil {
		_ = c.Conn.CloseWithError(closeErrCodeOK, "")
	}
	if c.PktConn != nil {
		_ = c.PktConn.Close()
	}
	return nil
}

// wrapIfConnectionClosed checks if the error returned by quic-go
// indicates that the QUIC connection has been permanently closed,
// and if so, wraps the error with coreErrs.ClosedError.
// PITFALL: sometimes quic-go has "internal errors" that are not net.Error,
// but we still need to treat them as ClosedError.
func wrapIfConnectionClosed(err error) error {
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Temporary() {
		return coreErrs.ClosedError{Err: err}
	} else {
		return err
	}
}

type tcpConn struct {
	Orig             quic.Stream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, coreErrs.DialError{Message: msg}
		}
		c.Established = true
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}

type udpIOImpl struct {
	Conn quic.Connection
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			// Connection error, this will stop the session manager
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}
