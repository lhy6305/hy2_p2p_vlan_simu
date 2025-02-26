package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"
)

// Variables that may be set by the user
var (
	config_file_path string = "config.json"
)

// Variables for json parsing
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

type MainProgramConfig_hy2_quic_global_struct struct {
	StreamRecvWindowInit    uint64   `json:"stream_recv_window_init"`
	StreamRecvWindowMax     uint64   `json:"stream_recv_window_max"`
	ConnRecvWindowInit      uint64   `json:"conn_recv_window_init"`
	ConnRecvWindowMax       uint64   `json:"conn_recv_window_max"`
	MaxIdleTimeout_d        Duration `json:"max_idle_timeout"`
	MaxIdleTimeout          time.Duration
	DisablePathMTUDiscovery bool `json:"disable_path_mtu_discovery"`
}

type MainProgramConfig_hy2_global_struct struct {
	BandwidthSendMax uint64   `json:"bandwidth_send_max"`
	BandwidthRecvMax uint64   `json:"bandwidth_recv_max"`
	AuthParam        string   `json:"auth_param"`
	AuthTimeout_d    Duration `json:"client_auth_timeout"`
	AuthTimeout      time.Duration
}

type MainProgramConfig_struct struct {
	Clog struct {
		LogFile             string `json:"log_file"`
		LogFile_obj         *os.File
		DebugMode           bool `json:"debug_mode"`
		TraceMode           bool `json:"trace_mode"`
		LogTraceToFileOnly  bool `json:"log_trace_to_file_only"`
		EnableColoredOutput bool `json:"enable_colored_output"`
	} `json:"clog"`

	FramePool struct {
		MaxPacketSize          int      `json:"max_packet_size"`
		IncompleteChunkTTL_d   Duration `json:"incomplete_chunk_ttl"`
		IncompleteChunkTTL     time.Duration
		ChunkCleanupInterval_d Duration `json:"chunk_cleanup_interval"`
		ChunkCleanupInterval   time.Duration
		MaxReadyFrames         int `json:"max_ready_frames"`
		const_FrameHeaderSize  int
	} `json:"frame_pool"`

	Vlan struct {
		NetDevice               string `json:"net_device"`
		CIDR                    string `json:"cidr"`
		CIDR_obj                *net.IPNet
		LocalRealMAC            string `json:"local_real_mac"`
		LocalRealMAC_obj        []byte
		LocalRealGatewayMAC     string `json:"local_real_gateway_mac"`
		LocalRealGatewayMAC_obj []byte
		LocalRealIP             string `json:"local_real_ip"`
		LocalRealIP_obj         []byte
		LocalVirtualIP          string `json:"local_virtual_ip"`
		LocalVirtualIP_obj      []byte
		PacketSendThreadCount   int64 `json:"packet_send_thread_count"`
		PacketRecv1ThreadCount  int64 `json:"packet_recv1_thread_count"`
		PacketRecv2ThreadCount  int64 `json:"packet_recv2_thread_count"`
		ParamCheckOK            bool
	} `json:"vlan"`

	Hy2 struct {
		CopyBufferSize int `json:"copy_buffer"`

		Client struct {
			MainProgramConfig_hy2_global_struct
			OpenStreamTimeout_d Duration `json:"open_stream_timeout"`
			OpenStreamTimeout   time.Duration
			ConnLocalAddr       string `json:"conn_local_addr"`
			TlsServerName       string `json:"tls_server_name"`
			TlsAllowInsecure    bool   `json:"tls_allow_insecure"`
			Quic                struct {
				MainProgramConfig_hy2_quic_global_struct
				KeepaliveInterval_d Duration `json:"keepalive_interval"`
				KeepaliveInterval   time.Duration
			} `json:"quic"`
		} `json:"client"`

		Server struct {
			MainProgramConfig_hy2_global_struct
			Quic struct {
				MainProgramConfig_hy2_quic_global_struct
				MaxIncomingStreams int64 `json:"max_incoming_streams"`
			} `json:"quic"`
			IgnoreClientBandwidth bool `json:"ignore_client_bandwidth"`
		} `json:"server"`

		Certs []struct {
			Cert       string `json:"cert"`
			PrivateKey string `json:"private_key"`
		} `json:"certs"`
		CertsObj []tls.Certificate
	} `json:"hy2"`
}

var MainProgramConfig = MainProgramConfig_struct{}

func init_default_config() {
	MainProgramConfig.Clog.LogFile = "hy2_p2p_vlan_log.txt"
	MainProgramConfig.Clog.DebugMode = false
	MainProgramConfig.Clog.TraceMode = false
	MainProgramConfig.Clog.LogTraceToFileOnly = true
	MainProgramConfig.Clog.EnableColoredOutput = true

	MainProgramConfig.FramePool.MaxPacketSize = 1200
	MainProgramConfig.FramePool.IncompleteChunkTTL_d = Duration{3000 * time.Millisecond}
	MainProgramConfig.FramePool.ChunkCleanupInterval_d = Duration{3000 * time.Millisecond}
	MainProgramConfig.FramePool.MaxReadyFrames = 512
	MainProgramConfig.FramePool.const_FrameHeaderSize = 12

	MainProgramConfig.Vlan.PacketSendThreadCount = 2
	MainProgramConfig.Vlan.PacketRecv1ThreadCount = 2
	MainProgramConfig.Vlan.PacketRecv2ThreadCount = 2
	MainProgramConfig.Vlan.ParamCheckOK = true

	MainProgramConfig.Hy2.CopyBufferSize = 32 * 1024

	MainProgramConfig.Hy2.Client.ConnLocalAddr = ""
	MainProgramConfig.Hy2.Client.TlsAllowInsecure = false
	MainProgramConfig.Hy2.Client.AuthParam = ""
	MainProgramConfig.Hy2.Client.TlsServerName = ""
	MainProgramConfig.Hy2.Client.BandwidthSendMax = 0
	MainProgramConfig.Hy2.Client.BandwidthRecvMax = 0
	MainProgramConfig.Hy2.Client.OpenStreamTimeout_d = Duration{3 * time.Second}
	MainProgramConfig.Hy2.Client.AuthTimeout_d = Duration{3 * time.Second}
	MainProgramConfig.Hy2.Client.Quic.MaxIdleTimeout_d = Duration{30 * time.Second}
	MainProgramConfig.Hy2.Client.Quic.KeepaliveInterval_d = Duration{10 * time.Second}
	MainProgramConfig.Hy2.Client.Quic.DisablePathMTUDiscovery = false
	MainProgramConfig.Hy2.Client.Quic.StreamRecvWindowInit = 0
	MainProgramConfig.Hy2.Client.Quic.StreamRecvWindowMax = 8 * 1024 * 1024
	MainProgramConfig.Hy2.Client.Quic.ConnRecvWindowInit = 0
	MainProgramConfig.Hy2.Client.Quic.ConnRecvWindowMax = 20 * 1024 * 1024

	MainProgramConfig.Hy2.Server.IgnoreClientBandwidth = false
	MainProgramConfig.Hy2.Server.AuthParam = ""
	MainProgramConfig.Hy2.Server.BandwidthSendMax = 0
	MainProgramConfig.Hy2.Server.BandwidthRecvMax = 0
	MainProgramConfig.Hy2.Server.AuthTimeout_d = Duration{3 * time.Second}
	MainProgramConfig.Hy2.Server.Quic.MaxIdleTimeout_d = Duration{30 * time.Second}
	MainProgramConfig.Hy2.Server.Quic.MaxIncomingStreams = 1024
	MainProgramConfig.Hy2.Server.Quic.DisablePathMTUDiscovery = false
	MainProgramConfig.Hy2.Server.Quic.StreamRecvWindowInit = 0
	MainProgramConfig.Hy2.Server.Quic.StreamRecvWindowMax = 8 * 1024 * 1024
	MainProgramConfig.Hy2.Server.Quic.ConnRecvWindowInit = 0
	MainProgramConfig.Hy2.Server.Quic.ConnRecvWindowMax = 20 * 1024 * 1024
}

func config_init1() {
	flag.StringVar(&config_file_path, "config", config_file_path, "")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "hy2_tnl program by ly65")
		fmt.Fprintf(flag.CommandLine.Output(), "\n")
		fmt.Fprintf(flag.CommandLine.Output(), "ly65-miao don't know how to use it, though...\r")
		fmt.Fprintf(flag.CommandLine.Output(), "                                             \n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags...]", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	init_default_config()

	config_file, err := os.Open("config.json")
	if err != nil {
		custom_log("Warn", "Config file not readable, using default config: %v", err)
		return
	}
	defer config_file.Close()

	decoder := json.NewDecoder(config_file)
	decoder.DisallowUnknownFields()
	err1 := decoder.Decode(&MainProgramConfig)

	if err1 != nil {
		ret, err := config_file.Seek(0, 0)
		if ret != 0 || err != nil {
			custom_log("Fatal", "Failed to parse config: %v", err)
			os.Exit(1)
			return
		}
		decoder = json.NewDecoder(config_file)
		err = decoder.Decode(&MainProgramConfig)
		if err != nil {
			custom_log("Fatal", "Failed to parse config: %v", err)
			os.Exit(1)
			return
		}
		custom_log("Warn", "Unknown fields found: %v", err1)
	}

	custom_log("Info", "Config file parsed successfully")
}

func config_init2() {
	var err error

	// copy Duration to time.Duration

	if len(MainProgramConfig.Clog.LogFile) > 0 {
		MainProgramConfig.Clog.LogFile_obj, err = os.OpenFile(MainProgramConfig.Clog.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			custom_log("Error", "Failed to open log file: %v", err)
			MainProgramConfig.Clog.LogFile_obj = nil
		}
	}

	MainProgramConfig.FramePool.IncompleteChunkTTL = MainProgramConfig.FramePool.IncompleteChunkTTL_d.Duration
	MainProgramConfig.FramePool.ChunkCleanupInterval = MainProgramConfig.FramePool.ChunkCleanupInterval_d.Duration

	MainProgramConfig.Vlan.LocalRealMAC_obj = mac_to_bytes(MainProgramConfig.Vlan.LocalRealMAC)
	MainProgramConfig.Vlan.LocalRealGatewayMAC_obj = mac_to_bytes(MainProgramConfig.Vlan.LocalRealGatewayMAC)
	MainProgramConfig.Vlan.LocalRealIP_obj = net.ParseIP(MainProgramConfig.Vlan.LocalRealIP).To4()
	MainProgramConfig.Vlan.LocalVirtualIP_obj = net.ParseIP(MainProgramConfig.Vlan.LocalVirtualIP).To4()
	if len(MainProgramConfig.Vlan.CIDR) > 0 {
		_, MainProgramConfig.Vlan.CIDR_obj, err = net.ParseCIDR(MainProgramConfig.Vlan.CIDR)
		if err != nil {
			custom_log("Error", "Failed to parse Vlan.CIDR %s: %v", MainProgramConfig.Vlan.CIDR, err)
			MainProgramConfig.Vlan.ParamCheckOK = false
		}
	}

	MainProgramConfig.Hy2.Client.AuthTimeout = MainProgramConfig.Hy2.Client.AuthTimeout_d.Duration
	MainProgramConfig.Hy2.Client.Quic.MaxIdleTimeout = MainProgramConfig.Hy2.Client.Quic.MaxIdleTimeout_d.Duration

	MainProgramConfig.Hy2.Client.OpenStreamTimeout = MainProgramConfig.Hy2.Client.OpenStreamTimeout_d.Duration
	MainProgramConfig.Hy2.Client.AuthTimeout = MainProgramConfig.Hy2.Client.AuthTimeout_d.Duration
	MainProgramConfig.Hy2.Client.Quic.MaxIdleTimeout = MainProgramConfig.Hy2.Client.Quic.MaxIdleTimeout_d.Duration
	MainProgramConfig.Hy2.Client.Quic.KeepaliveInterval = MainProgramConfig.Hy2.Client.Quic.KeepaliveInterval_d.Duration
	MainProgramConfig.Hy2.Server.AuthTimeout = MainProgramConfig.Hy2.Server.AuthTimeout_d.Duration
	MainProgramConfig.Hy2.Server.Quic.MaxIdleTimeout = MainProgramConfig.Hy2.Server.Quic.MaxIdleTimeout_d.Duration

	// parse certs

	MainProgramConfig.Hy2.CertsObj = make([]tls.Certificate, 0)
	for _, conf := range MainProgramConfig.Hy2.Certs {
		cert_str, err := ioutil.ReadFile(conf.Cert)
		if err != nil {
			custom_log("Error", "Failed to read certificate %s: %v", conf.Cert, err)
			continue
		}

		private_key_str, err := ioutil.ReadFile(conf.PrivateKey)
		if err != nil {
			custom_log("Error", "Failed to read private key %s: %v", conf.PrivateKey, err)
			continue
		}

		cert_obj, err := tls.X509KeyPair(cert_str, private_key_str)
		if err != nil {
			custom_log("Error", "Failed to load certificate %s: %v", conf.Cert, err)
			continue
		}

		MainProgramConfig.Hy2.CertsObj = append(MainProgramConfig.Hy2.CertsObj, cert_obj)
		custom_log("Info", "Certificate file %s loaded successfully", conf.Cert)
	}
}

func config_init3() {

	//framepool

	if MainProgramConfig.FramePool.MaxPacketSize <= MainProgramConfig.FramePool.const_FrameHeaderSize {
		custom_log("Warn", "FramePool.MaxPacketSize must > %d. Setting to default value (1200)", MainProgramConfig.FramePool.const_FrameHeaderSize)
		MainProgramConfig.FramePool.MaxPacketSize = 1200
		os.Exit(1)
		return
	}
	if MainProgramConfig.FramePool.MaxPacketSize > 1200 {
		custom_log("Warn", "FramePool.MaxPacketSize must <= 1200. Setting to default value (1200)") //hy2_quic.internal.wire.datagram_frame.go -> MaxDatagramSize
		MainProgramConfig.FramePool.MaxPacketSize = 1200
		return
	}

	//hy2

	if MainProgramConfig.Hy2.Client.TlsAllowInsecure {
		custom_log("Warn", "TlsAllowInsecure enabled on client")
	}
	if len(MainProgramConfig.Hy2.Server.AuthParam) <= 0 {
		custom_log("Warn", "Hy2.Server.AuthParam is empty. The server will accept any connection. This is not recommended.")
	}

	//vlan
	if len(MainProgramConfig.Vlan.CIDR) <= 0 {
		custom_log("Warn", "Vlan.CIDR is empty. The Vlan function will not work properly.")
		MainProgramConfig.Vlan.ParamCheckOK = false
	}
	if len(MainProgramConfig.Vlan.LocalRealMAC) <= 0 {
		custom_log("Warn", "Vlan.LocalRealMAC is empty. The Vlan function will not work properly.")
		MainProgramConfig.Vlan.ParamCheckOK = false
	}
	if len(MainProgramConfig.Vlan.LocalRealGatewayMAC) <= 0 {
		custom_log("Warn", "Vlan.LocalRealGatewayMAC is empty. The Vlan function will not work properly.")
		MainProgramConfig.Vlan.ParamCheckOK = false
	}
	if len(MainProgramConfig.Vlan.LocalRealIP) <= 0 {
		custom_log("Warn", "Vlan.LocalRealIP is empty. The Vlan function will not work properly.")
		MainProgramConfig.Vlan.ParamCheckOK = false
	}
	if len(MainProgramConfig.Vlan.LocalVirtualIP) <= 0 {
		custom_log("Warn", "Vlan.LocalVirtualIP is empty. The Vlan function will not work properly.")
		MainProgramConfig.Vlan.ParamCheckOK = false
	} else {
		custom_log("Info", "Vlan.LocalVirtualIP is %s", MainProgramConfig.Vlan.LocalVirtualIP)
	}
	if len(MainProgramConfig.Vlan.CIDR) > 0 && len(MainProgramConfig.Vlan.LocalVirtualIP) > 0 {
		if !MainProgramConfig.Vlan.CIDR_obj.Contains(MainProgramConfig.Vlan.LocalVirtualIP_obj) {
			custom_log("Error", "Vlan.CIDR %s does not contain Vlan.LocalVirtualIP: %s", MainProgramConfig.Vlan.CIDR, MainProgramConfig.Vlan.LocalVirtualIP)
			MainProgramConfig.Vlan.ParamCheckOK = false
		}
	}
	if MainProgramConfig.Vlan.PacketSendThreadCount <= 0 {
		custom_log("Error", "Vlan.PacketSendThreadCount is %d (>=0 expected). The Vlan function will not work properly.", MainProgramConfig.Vlan.PacketSendThreadCount)
		MainProgramConfig.Vlan.ParamCheckOK = false
	}
	if MainProgramConfig.Vlan.PacketRecv1ThreadCount <= 0 {
		custom_log("Error", "Vlan.PacketRecv1ThreadCount is %d (>=0 expected). The Vlan function will not work properly.", MainProgramConfig.Vlan.PacketRecv1ThreadCount)
		MainProgramConfig.Vlan.ParamCheckOK = false
	}
	if MainProgramConfig.Vlan.PacketRecv2ThreadCount <= 0 {
		custom_log("Error", "Vlan.PacketRecv2ThreadCount is %d (>=0 expected). The Vlan function will not work properly.", MainProgramConfig.Vlan.PacketRecv2ThreadCount)
		MainProgramConfig.Vlan.ParamCheckOK = false
	}
}
