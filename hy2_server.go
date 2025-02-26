package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	hy2_server "github.com/apernet/hysteria/core/v2/server"
	hy2_quic "github.com/apernet/quic-go"
	hy2_http3 "github.com/apernet/quic-go/http3"
)

var (
	hy2_server_instance                  *hy2_server.ServerImpl = nil
	hy2_server_instance_mutex            sync.Mutex
	hy2_server_is_client_connected       bool         = false
	hy2_server_is_client_connected_mutex sync.RWMutex = sync.RWMutex{}
	hy2_server_authenticator                          = &hy2_server_authenticator_struct{}
)

type hy2_server_authenticator_struct struct{}

func (_ hy2_server_authenticator_struct) Authenticate(peer_addr net.Addr, auth_param string, peer_recv_rate uint64) (ok bool, id string) {
	if len(MainProgramConfig.Hy2.Server.AuthParam) <= 0 || auth_param == MainProgramConfig.Hy2.Server.AuthParam {
		return true, gen_random_id(16)
	}
	return false, ""
}

func hy2_server_init(addr string) bool {

	if !hy2_server_instance_mutex.TryLock() {
		custom_log("Error", "A Hy2 server instance is already running! Close it before making a new one.")
		return false
	}
	defer hy2_server_instance_mutex.Unlock()

	hy2_server_is_client_connected_mutex.Lock()
	defer hy2_server_is_client_connected_mutex.Unlock()

	if !hy2_quic_conn_mutex.TryLock() {
		custom_log("Error", "A Hy2 conn instance is already established! Close it before making a new one")
		return false
	}
	defer hy2_quic_conn_mutex.Unlock()

	if hy2_quic_conn != nil {
		custom_log("Info", "Closing old Hy2 quic conn...")
		(*hy2_quic_conn).CloseWithError(0x0100, "Peer closed connection")
		hy2_quic_conn = nil
	}
	if hy2_server_instance != nil {
		custom_log("Info", "Closing old Hy2 server...")
		hy2_server_instance.Close()
		hy2_server_instance = nil
	}
	hy2_server_is_client_connected = false
	custom_log("Info", "Trying to create Hy2 server on address %s ...", addr)
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		custom_log("Error", "Failed parse server address %s: %v", addr, err)
		return false
	}
	pconn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		custom_log("Error", "Failed to bind udp address %s: %v", addr, err)
		return false
	}
	hy2_server_instance, err = hy2_server.NewServer(&hy2_server.Config{
		TLSConfig: hy2_server.TLSConfig{
			Certificates:   MainProgramConfig.Hy2.CertsObj,
			GetCertificate: nil,
		},
		QUICConfig: hy2_server.QUICConfig{
			InitialStreamReceiveWindow:     MainProgramConfig.Hy2.Server.Quic.StreamRecvWindowInit,
			MaxStreamReceiveWindow:         MainProgramConfig.Hy2.Server.Quic.StreamRecvWindowMax,
			InitialConnectionReceiveWindow: MainProgramConfig.Hy2.Server.Quic.ConnRecvWindowInit,
			MaxConnectionReceiveWindow:     MainProgramConfig.Hy2.Server.Quic.ConnRecvWindowMax,
			MaxIdleTimeout:                 MainProgramConfig.Hy2.Server.Quic.MaxIdleTimeout,
			MaxIncomingStreams:             MainProgramConfig.Hy2.Server.Quic.MaxIncomingStreams,
			DisablePathMTUDiscovery:        MainProgramConfig.Hy2.Server.Quic.DisablePathMTUDiscovery,
		},
		Conn:        pconn,
		RequestHook: nil,
		Outbound:    nil,
		BandwidthConfig: hy2_server.BandwidthConfig{
			MaxTx: MainProgramConfig.Hy2.Server.BandwidthSendMax,
			MaxRx: MainProgramConfig.Hy2.Server.BandwidthRecvMax,
		},
		IgnoreClientBandwidth: MainProgramConfig.Hy2.Server.IgnoreClientBandwidth,
		DisableUDP:            true,
		UDPIdleTimeout:        60 * time.Second,
		Authenticator:         hy2_server_authenticator,
		EventLogger:           nil,
		TrafficLogger:         nil,
		MasqHandler:           nil, // http content handler when auth fail
	})
	if err != nil {
		custom_log("Error", "Failed to create Hy2 server on address %s: %v", addr, err)
		return false
	}
	custom_log("Info", "Hy2 server on address %s created", addr)
	return true
}

func hy2_server_serve_loop() {
	hy2_server_instance_mutex.Lock()
	defer hy2_server_instance_mutex.Unlock()

	if hy2_server_instance == nil {
		custom_log("Error", "hy2_server_instance is nil")
		return
	}

	for {
		conn, err := hy2_server_instance.Listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, hy2_quic.ErrServerClosed) {
				custom_log("Info", "Hy2 server closed")
				return
			}
			custom_log("Error", "Failed to keep Hy2 server: %v", err)
			return
		}
		hy2_server_is_client_connected_mutex.RLock()
		if hy2_server_is_client_connected {
			hy2_server_is_client_connected_mutex.RUnlock()
			conn.CloseWithError(0x0107, "Request Rejected: Only one client could connect at once")
			custom_log("Info", "Incoming Hy2 conn %s rejected: Only one client could connect at once", conn.RemoteAddr())
		}
		hy2_server_is_client_connected_mutex.RUnlock()
		go hy2_server_handle_connection(conn)
	}
}

func hy2_server_handle_connection(conn hy2_quic.Connection) {
	custom_log("Info", "Incoming Hy2 conn %s", conn.RemoteAddr())
	hy2_server_is_client_connected_mutex.RLock()
	if hy2_server_is_client_connected {
		hy2_server_is_client_connected_mutex.RUnlock()
		custom_log("Warn", "Client %s request rejected: Client already connected", conn.RemoteAddr())
		conn.CloseWithError(0x010b, "Request rejected: Client already connected")
		return
	}
	hy2_server_is_client_connected_mutex.RUnlock()

	handler := hy2_server.NewH3sHandler(hy2_server_instance.Config, conn)
	h3s := hy2_http3.Server{
		Handler: handler,
		StreamHijacker: func(ft hy2_http3.FrameType, id hy2_quic.ConnectionTracingID, stream hy2_quic.Stream, err error) (bool, error) {
			handler.AuthFinishedMutex.Lock()
			if !handler.AuthFinished {
				conn.CloseWithError(0x010b, "Request Rejected: Unknown packet before auth")
				custom_log("Warn", "Client %s sent an unknown packet before auth", conn.RemoteAddr())
				handler.AuthFinished = true
				handler.AuthFinishedChan <- struct{}{}
				close(handler.AuthFinishedChan)
				handler.AuthFinishedMutex.Unlock()
				return true, nil
			}
			handler.AuthFinishedMutex.Unlock()
			custom_log("Trace", "StreamHijacker called")
			return true, nil
		},
	}

	time.AfterFunc(MainProgramConfig.Hy2.Server.AuthTimeout, func() {
		handler.AuthFinishedMutex.Lock()
		if !handler.AuthFinished {
			conn.CloseWithError(0x010b, "Request Rejected: Auth timeout")
			custom_log("Warn", "Client %s auth timed out in %s", conn.RemoteAddr(), MainProgramConfig.Hy2.Server.AuthTimeout.String())
			handler.AuthFinished = true
			handler.AuthFinishedChan <- struct{}{}
			close(handler.AuthFinishedChan)
			handler.AuthFinishedMutex.Unlock()
			return
		}
		handler.AuthFinishedMutex.Unlock()
	})

	go func() {
		<-handler.AuthFinishedChan

		if !handler.Authenticated {
			custom_log("Warn", "Hy2 quic client %s failed to auth", conn.RemoteAddr())
			conn.CloseWithError(0x010b, "Request Rejected: Failed to auth client")
			return
		}

		if !hy2_quic_conn_mutex.TryLock() {
			custom_log("Error", "A Hy2 conn instance is already established! Close it before making a new one")
			conn.CloseWithError(0x010b, "Request rejected: A Hy2 conn instance is already started")
			return
		}

		if hy2_quic_conn != nil {
			custom_log("Logic Error", "Closing old Hy2 quic conn...(this should not happen!)")
			(*hy2_quic_conn).CloseWithError(0x0102, "Internal Logic Error")
			hy2_quic_conn = nil
			hy2_quic_conn_mutex.Unlock()
			return
		}
		hy2_quic_conn = &conn
		hy2_quic_conn_mutex.Unlock()
		custom_log("Info", "Incoming Hy2 conn %s established", conn.RemoteAddr())
	}()

	err := h3s.ServeQUICConn(conn) // will block here
	conn.CloseWithError(0x0100, "Connection Closed: All OK")

	hy2_server_is_client_connected_mutex.Lock()
	hy2_server_is_client_connected = false
	hy2_server_is_client_connected_mutex.Unlock()

	if err != nil {
		if aerr, ok := err.(*hy2_quic.ApplicationError); ok && aerr.ErrorCode == 0x010c {
			custom_log("Info", "Hy2 quic conn %s closed: Manual Disconnect", conn.RemoteAddr())
			return
		}
		custom_log("Warn", "Failed to serve Hy2 quic client %s: %v", conn.RemoteAddr(), err)
		return
	}
}

func hy2_server_start(addr string) bool {
	if !hy2_server_init(addr) {
		return false
	}
	go hy2_server_serve_loop()
	return true
}
