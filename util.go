package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

func gen_random_id(length int) string {
	rand_bytes := make([]byte, (length+1)/2)
	_, err := rand.Read(rand_bytes)
	if err != nil {
		custom_log("Error", "GenRandomId() failed: %v", err)
		return "Fallback_AuthID_because_GenRandomId_Failed"
	}
	return hex.EncodeToString(rand_bytes)[:length]
}

func mac_to_bytes(mac string) []byte {
	mac_obj, err := net.ParseMAC(mac)
	if err != nil {
		custom_log("Error", "Invalid MAC address %s: %v", mac, err)
		return []byte{0, 0, 0, 0, 0, 0}
	}
	return mac_obj
}

func dump_bytes(data []byte) {
	hex_string := fmt.Sprintf("%x", data)

	var sb strings.Builder
	for i := 0; i < len(hex_string); i += 2 {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(hex_string[i : i+2])
	}

	custom_log("Trace", "dump_bytes(): %s", sb.String())
}
