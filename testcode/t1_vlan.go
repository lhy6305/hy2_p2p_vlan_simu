package main

import (
	"fmt"
	//"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	NetDevice       string = "\\Device\\NPF_{0D2B28BC-4C96-4B34-8E62-AAC9CD72AC59}"
	RealLocalIP     string = "192.168.1.14"
	RealLocalIP_obj []byte = []byte{192, 168, 1, 14}
	LocalIP         string = "192.168.1.253"
	LocalIP_obj     []byte = []byte{192, 168, 1, 253}
	RemoteIP        string = "10.0.0.1"
	RemoteIP_obj    []byte = []byte{10, 0, 0, 1}
	RemoteARPIP     string = "192.168.1.254"
	RemoteARPIP_obj []byte = []byte{192, 168, 1, 254}
	LocalMAC_obj    []byte = []byte{0x1E, 0x90, 0x42, 0xD0, 0xEE, 0x00}
	//RemoteMAC_obj   []byte = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	RemoteMAC_obj []byte = []byte{0xab, 0xcd, 0xef, 0x00, 0x01, 0x02}
)

func main1() {
	handle, err := pcap.OpenLive(NetDevice, 1600, true, pcap.BlockForever)
	if err != nil {
		custom_log("Error", "Failed to open device %s: %v", NetDevice, err)
		return
	}
	filter := fmt.Sprintf("(ip and dst host %s) or (arp and dst host %s and arp[6:2] = 1)", RemoteIP, RemoteIP)
	//filter := fmt.Sprintf("ip and dst host %s", RemoteIP)
	if err := handle.SetBPFFilter(filter); err != nil {
		custom_log("Error", "Failed to set BPF filter %s: %v", filter, err)
		handle.Close()
		return
	}
	for {
		if handle == nil {
			custom_log("Trace", "handle is nil")
			time.Sleep(1000 * time.Millisecond)
			continue
		}
		eth := layers.Ethernet{
			SrcMAC:       RemoteMAC_obj,
			DstMAC:       LocalMAC_obj,
			EthernetType: layers.EthernetTypeARP,
		}
		arp_resp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   RemoteMAC_obj,
			SourceProtAddress: RemoteARPIP_obj,
			DstHwAddress:      []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			DstProtAddress:    RemoteARPIP_obj,
		}
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		gopacket.SerializeLayers(buffer, opts, &eth, &arp_resp)
		if err := handle.WritePacketData(buffer.Bytes()); err != nil {
			custom_log("Trace", "Failed to inject ARP announce: %v", err)
		} else {
			custom_log("Trace", "Injected ARP announce")
		}
		/*
			eth := layers.Ethernet{
				SrcMAC:       RemoteMAC_obj,
				DstMAC:       LocalMAC_obj,
				EthernetType: layers.EthernetTypeARP,
			}
			arp_resp := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         layers.ARPReply,
				SourceHwAddress:   RemoteMAC_obj,
				SourceProtAddress: RemoteARPIP_obj,
				DstHwAddress:      LocalMAC_obj,
				DstProtAddress:    RealLocalIP_obj,
			}
			buffer := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			gopacket.SerializeLayers(buffer, opts, &eth, &arp_resp)
			if err := handle.WritePacketData(buffer.Bytes()); err != nil {
				custom_log("Trace", "Failed to inject ARP announce: %v", err)
			} else {
				custom_log("Trace", "Injected ARP announce")
			}
		*/
		time.Sleep(1000 * time.Millisecond)
	}
}
