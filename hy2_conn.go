package main

import (
	"sync"

	hy2_quic "github.com/apernet/quic-go"
)

var (
	hy2_quic_conn       *hy2_quic.Connection = nil
	hy2_quic_conn_mutex sync.RWMutex
)
