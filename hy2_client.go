package main

import (
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	hy2_client "github.com/apernet/hysteria/core/v2/client"
)

var (
	hy2_client_instance       *hy2_client.ClientImpl = nil
	hy2_client_instance_mutex sync.Mutex
)

type hy2ConnFactory struct {
	PeerAddr    string
	PeerUdpAddr *net.UDPAddr
}

func (_ *hy2ConnFactory) New(server_peer_addr net.Addr) (net.PacketConn, error) {
	if len(MainProgramConfig.Hy2.Client.ConnLocalAddr) <= 0 {
		return net.ListenUDP("udp", nil)
	}
	uaddr, err := net.ResolveUDPAddr("udp", MainProgramConfig.Hy2.Client.ConnLocalAddr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", uaddr)
}

func hy2_client_start(addr string) bool {
	hy2_client_instance_mutex.Lock()
	defer hy2_client_instance_mutex.Unlock()

	if !hy2_quic_conn_mutex.TryLock() {
		custom_log("Warn", "A Hy2 conn instance is already established! Close it before making a new one")
	}

	if hy2_quic_conn != nil {
		custom_log("Info", "Closing old Hy2 quic conn...")
		(*hy2_quic_conn).CloseWithError(0x0100, "Peer closed connection")
		hy2_quic_conn = nil
	}
	if hy2_client_instance != nil {
		custom_log("Info", "Closing old Hy2 client...")
		hy2_client_instance.Close()
		hy2_client_instance = nil
	}
	custom_log("Info", "Trying to create Hy2 client on address %s ...", addr)
	var err error
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		custom_log("Error", "Failed parse server address %s: %v", addr, err)
		hy2_quic_conn_mutex.Unlock()
		return false
	}
	hy2_client_instance, err = hy2_client.NewClient(&hy2_client.Config{
		ConnFactory: &hy2ConnFactory{PeerAddr: addr, PeerUdpAddr: udp_addr},
		ServerAddr:  udp_addr,
		Auth:        MainProgramConfig.Hy2.Client.AuthParam,
		TLSConfig: hy2_client.TLSConfig{
			ServerName:         MainProgramConfig.Hy2.Client.TlsServerName,
			InsecureSkipVerify: true, // to enable VerifyPeerCertificate fallback
			VerifyPeerCertificate: func(peer_certs [][]byte, verified_cert_chains [][]*x509.Certificate) error {
				if MainProgramConfig.Hy2.Client.TlsAllowInsecure {
					return nil
				}
				if len(MainProgramConfig.Hy2.CertsObj) <= 0 {
					custom_log("Error", "No certs found in config. VerifyPeerCertificate() will always reject server response")
					return fmt.Errorf("No certs found in config")
				}
				root_ca_list := x509.NewCertPool()
				sys_root_ca_list, err := x509.SystemCertPool()
				if err == nil && sys_root_ca_list != nil {
					root_ca_list = sys_root_ca_list
				}

				for _, cert := range MainProgramConfig.Hy2.CertsObj {
					cert, err := x509.ParseCertificate(cert.Certificate[0])
					if err != nil {
						custom_log("Logic Error", "Failed to parse certificate: %v (this should not happen)", err)
						return fmt.Errorf("Failed to parse certificate: %v", err)
					}
					root_ca_list.AddCert(cert)
				}

				for _, peer_cert := range peer_certs {
					cert, err := x509.ParseCertificate(peer_cert)
					if err != nil {
						return fmt.Errorf("Failed to parse peer certificate: %v", err)
					}

					_, err = cert.Verify(x509.VerifyOptions{
						Roots:         root_ca_list,
						KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
						CurrentTime:   cert.NotBefore,
						Intermediates: nil,
					})

					if err != nil {
						return fmt.Errorf("Certificate verification failed: %v", err)
					}
				}
				return nil
			},
			RootCAs: nil,
		},
		QUICConfig: hy2_client.QUICConfig{
			InitialStreamReceiveWindow:     MainProgramConfig.Hy2.Client.Quic.StreamRecvWindowInit,
			MaxStreamReceiveWindow:         MainProgramConfig.Hy2.Client.Quic.StreamRecvWindowMax,
			InitialConnectionReceiveWindow: MainProgramConfig.Hy2.Client.Quic.ConnRecvWindowInit,
			MaxConnectionReceiveWindow:     MainProgramConfig.Hy2.Client.Quic.ConnRecvWindowMax,
			MaxIdleTimeout:                 MainProgramConfig.Hy2.Client.Quic.MaxIdleTimeout,
			KeepAlivePeriod:                MainProgramConfig.Hy2.Client.Quic.KeepaliveInterval,
			DisablePathMTUDiscovery:        MainProgramConfig.Hy2.Client.Quic.DisablePathMTUDiscovery,
		},
		BandwidthConfig: hy2_client.BandwidthConfig{
			MaxTx: MainProgramConfig.Hy2.Client.BandwidthSendMax,
			MaxRx: MainProgramConfig.Hy2.Client.BandwidthRecvMax,
		},
		FastOpen: false,
	})
	if err != nil {
		custom_log("Error", "Failed to create Hy2 client for remote %s: %v", addr, err)
		hy2_quic_conn_mutex.Unlock()
		return false
	}

	time.AfterFunc(MainProgramConfig.Hy2.Client.AuthTimeout, func() {
		hy2_client_instance.AuthFinishedMutex.Lock()
		if !hy2_client_instance.AuthFinished {
			hy2_client_instance.Close()
			custom_log("Warn", "Hy2 client to remote %s auth timed out in %s", addr, MainProgramConfig.Hy2.Client.AuthTimeout.String())
			hy2_client_instance.AuthFinished = true
			hy2_client_instance.AuthFinishedMutex.Unlock()
			return
		}
		hy2_client_instance.AuthFinishedMutex.Unlock()
		if !hy2_client_instance.Authenticated {
			hy2_client_instance.Close()
			custom_log("Warn", "Hy2 quic client to remote %s failed to auth", addr)
			return
		}
	})

	_, err = hy2_client_instance.Connect()

	if err != nil {
		custom_log("Error", "Failed to connect Hy2 client to remote %s: %v", addr, err)
		return false
	}
	hy2_quic_conn = &hy2_client_instance.Conn
	hy2_quic_conn_mutex.Unlock()
	custom_log("Info", "Hy2 client on address %s created", addr)
	return true
}
