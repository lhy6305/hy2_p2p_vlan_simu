package main

import (
	"bytes"
	"context"
	//"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	vlan_netdevice_handle                 *pcap.Handle
	vlan_remote_ip_to_mac_map             = make(map[string][]byte)
	vlan_remote_ip_to_mac_map_mutex       sync.RWMutex
	vlan_packet_recv1_task_chan           = make(chan *[]byte, 128)
	vlan_packet_send_worker_count         = &atomic.Int64{} // worker id start from 1
	vlan_packet_recv1_worker_count        = &atomic.Int64{} // worker id start from 1
	vlan_packet_recv2_worker_count        = &atomic.Int64{} // worker id start from 1
	vlan_packet_send_worker_cleanup_chan  = make(chan struct{}, 1)
	vlan_packet_recv1_worker_cleanup_chan = make(chan struct{}, 1)
	vlan_packet_recv2_worker_cleanup_chan = make(chan struct{}, 1)
)

// The return value of vlan_netdevice_handle.WritePacketData() may be ignored, as the packet will still be inserted normally even if an error occurs

func vlan_list_all_net_device() []pcap.Interface {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		custom_log("Error", "Failed to list net devices: %v", err)
		return make([]pcap.Interface, 0)
	}
	return ifs
}

func vlan_open_netdevice() bool {
	if vlan_netdevice_handle != nil {
		custom_log("Debug", "Closing existing handle")
		(*vlan_netdevice_handle).Close()
		vlan_netdevice_handle = nil
	}
	handle, err := pcap.OpenLive(MainProgramConfig.Vlan.NetDevice, 65535, true, pcap.BlockForever)
	if err != nil {
		custom_log("Error", "Failed to open device %s: %v", MainProgramConfig.Vlan.NetDevice, err)
		return false
	}
	/*
		filter := fmt.Sprintf("((ether dst host %s) and (dst net %s)) or (arp and arp[6:2] = 1)", MainProgramConfig.Vlan.LocalRealGatewayMAC, MainProgramConfig.Vlan.CIDR)
		if err := handle.SetBPFFilter(filter); err != nil {
			custom_log("Error", "Failed to set BPF filter %s: %v", filter, err)
			handle.Close()
			return false
		}
	*/
	vlan_netdevice_handle = handle
	return true
}

// async call, run once
func vlan_data_copier2_worker_loop() {
	for {
		if hy2_quic_conn == nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		packet, err := (*hy2_quic_conn).ReceiveDatagram(context.Background())
		if err != nil {
			custom_log("Error", "Failed to read from remote: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		custom_log("Trace", "Hy2 conn recv from remote: %d bytes", len(packet))
		select {
		case vlan_packet_recv1_task_chan <- &packet:
		default:
			custom_log("Warn", "vlan_packet_recv1_chan is full")
		}
	}
	custom_log("Logic Error", "vlan_start_data_copier().loop1 returns unexpectedly")
}

// async call
func vlan_packet_send_worker_loop() {
	vlan_packet_send_worker_count.Add(1)
	var ldatabuffer = make([]byte, 0, 65535)
	var data []byte
	var err error
	for {
		//select {
		//case data = <-vlan_packet_send_task_chan:
		data, _, err = vlan_netdevice_handle.ZeroCopyReadPacketData()
		if err != nil {
			custom_log("Error", "Failed to ZeroCopyReadPacketData: %v", err)
			break
		}
		ldatabuffer = append(ldatabuffer[:0], data...)
		if len(ldatabuffer) <= 0 {
			continue
		}
		packet := gopacket.NewPacket(ldatabuffer, layers.LayerTypeEthernet, gopacket.DecodeOptions{
			Lazy:                     true,
			NoCopy:                   true,
			SkipDecodeRecovery:       false,
			DecodeStreamsAsDatagrams: false,
		})
		if hook_arp_handler(packet) { // check and block arp request
			continue
		}
		if hy2_quic_conn == nil {
			continue
		}
		modified_packet := vlan_modify_packet_on_send(packet)
		if len(modified_packet) <= 0 {
			continue
		}
		for _, item := range framepool_split_chunk(modified_packet) {
			if err := (*hy2_quic_conn).SendDatagram(item); err != nil {
				custom_log("Warn", "Failed to send packet (%d bytes) to remote: %v", len(item), err)
			} else {
				custom_log("Trace", "Hy2 conn sent packet to remote: %d bytes", len(item))
			}
		}
		/*
			case <-vlan_packet_send_worker_cleanup_chan:
				vlan_packet_send_worker_count.Add(-1)
				custom_log("Trace", "VlanPacketSendWorker #%d exits", vlan_packet_send_worker_count.Load()+1)
				return
			}
		*/
	}
}

// async call
func vlan_packet_recv1_worker_loop() {
	vlan_packet_recv1_worker_count.Add(1)
	var packet *[]byte
	for {
		select {
		case packet = <-vlan_packet_recv1_task_chan:
			framepool_add(packet)
		case <-vlan_packet_recv1_worker_cleanup_chan:
			vlan_packet_recv1_worker_count.Add(-1)
			custom_log("Trace", "VlanPacketRecv1Worker #%d exits", vlan_packet_recv1_worker_count.Load()+1)
			return
		}
	}
}

// async call
func vlan_packet_recv2_worker_loop() {
	vlan_packet_recv2_worker_count.Add(1)
	for {
		select {
		case data, ok := <-frame_pool.ready_chan:
			if !ok {
				continue
			}
			modified_packet := vlan_modify_packet_on_recv(bytes.Join(data, nil))
			if len(modified_packet) <= 0 {
				continue
			}
			if vlan_netdevice_handle == nil {
				continue
			}
			_ = vlan_netdevice_handle.WritePacketData(modified_packet)
			custom_log("Trace", "Sent packet to local network: %d bytes", len(modified_packet))
		case <-vlan_packet_recv2_worker_cleanup_chan:
			vlan_packet_recv2_worker_count.Add(-1)
			custom_log("Trace", "VlanPacketRecv2Worker #%d exits", vlan_packet_recv2_worker_count.Load()+1)
			return
		}
	}
}

func vlan_modify_packet_on_send(packet gopacket.Packet) []byte {
	if packet.LinkLayer() == nil {
		custom_log("Trace", "Incoming packet missing LinkLayer")
		dump_bytes(packet.Data())
		return []byte{}
	}

	layer_eth, ok := packet.LinkLayer().(*layers.Ethernet)
	if !ok {
		custom_log("Trace", "Incoming packet's LinkLayer type is not Ethernet")
		dump_bytes(packet.Data())
		return []byte{}
	}

	if packet.NetworkLayer() == nil {
		custom_log("Trace", "Incoming packet missing NetworkLayer")
		dump_bytes(packet.Data())
		return []byte{}
	}
	layer_ipv4, ok := packet.NetworkLayer().(*layers.IPv4)
	if !ok {
		custom_log("Trace", "Incoming packet's NetworkLayer is not IPv4")
		dump_bytes(packet.Data())
		return []byte{}
	}

	// Start of packet processing (on send)

	if !MainProgramConfig.Vlan.CIDR_obj.Contains((*layer_ipv4).DstIP) {
		custom_log("Trace", "Outgoing packet's DstIP %s is not in CIDR", (*layer_ipv4).DstIP)
		return []byte{}
	}

	//custom_log("Trace", "vlan_modify_packet_on_send() before modify:")
	//dump_bytes(packet.Data())

	vlan_remote_ip_to_mac_map_mutex.RLock()
	if _, ok = vlan_remote_ip_to_mac_map[string((*layer_ipv4).DstIP)]; !ok {
		vlan_remote_ip_to_mac_map_mutex.RUnlock()
		vlan_remote_ip_to_mac_map_mutex.Lock()
		vlan_remote_ip_to_mac_map[string((*layer_ipv4).DstIP)] = bytes.Clone((*layer_eth).DstMAC)
		vlan_remote_ip_to_mac_map_mutex.Unlock()
	} else {
		vlan_remote_ip_to_mac_map_mutex.RUnlock()
	}

	(*layer_eth).SrcMAC = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	(*layer_eth).DstMAC = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	copy((*layer_ipv4).SrcIP, MainProgramConfig.Vlan.LocalVirtualIP_obj)

	// End of packet processing (on send)

	_, ok = packet.TransportLayer().(*layers.TCP)
	if ok {
		packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())
	} else {
		_, ok = packet.TransportLayer().(*layers.UDP)
		if ok {
			packet.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(packet.NetworkLayer())
		} else {
			custom_log("Error", "Unsupported TransportLayer type")
			return []byte{}
		}
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializePacket(buffer, opts, packet)
	if err != nil {
		custom_log("Error", "Failed to serialize layers for modified packet: %v", err)
		return []byte{}
	}

	//custom_log("Trace", "vlan_modify_packet_on_send() after modify:")
	//dump_bytes(buffer.Bytes())

	return buffer.Bytes()
}

func vlan_modify_packet_on_recv(data []byte) []byte {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{
		Lazy:                     true,
		NoCopy:                   true,
		SkipDecodeRecovery:       false,
		DecodeStreamsAsDatagrams: false,
	})
	if packet.LinkLayer() == nil {
		custom_log("Trace", "Incoming packet missing LinkLayer")
		dump_bytes(packet.Data())
		return []byte{}
	}

	layer_eth, ok := packet.LinkLayer().(*layers.Ethernet)
	if !ok {
		custom_log("Trace", "Incoming packet's LinkLayer type is not Ethernet")
		dump_bytes(packet.Data())
		return []byte{}
	}

	if packet.NetworkLayer() == nil {
		custom_log("Trace", "Incoming packet missing NetworkLayer")
		dump_bytes(packet.Data())
		return []byte{}
	}
	layer_ipv4, ok := packet.NetworkLayer().(*layers.IPv4)
	if !ok {
		custom_log("Trace", "Incoming packet's NetworkLayer is not IPv4")
		dump_bytes(packet.Data())
		return []byte{}
	}

	// Start of packet processing (on recv)

	if !bytes.Equal((*layer_ipv4).DstIP, MainProgramConfig.Vlan.LocalVirtualIP_obj) {
		custom_log("Trace", "Incoming packet's DstIP is not LocalVirtualIP")
		return []byte{}
	}

	//custom_log("Trace", "vlan_modify_packet_on_recv() before modify:")
	//dump_bytes(packet.Data())

	vlan_remote_ip_to_mac_map_mutex.RLock()
	if _, ok := vlan_remote_ip_to_mac_map[string((*layer_ipv4).SrcIP)]; ok {
		copy((*layer_eth).SrcMAC, vlan_remote_ip_to_mac_map[string((*layer_ipv4).SrcIP)])
		vlan_remote_ip_to_mac_map_mutex.RUnlock()
	} else {
		vlan_remote_ip_to_mac_map_mutex.RUnlock()
		copy((*layer_eth).SrcMAC, MainProgramConfig.Vlan.LocalRealGatewayMAC_obj)
	}

	copy((*layer_eth).DstMAC, MainProgramConfig.Vlan.LocalRealMAC_obj)

	copy((*layer_ipv4).DstIP, MainProgramConfig.Vlan.LocalRealIP_obj)

	// End of packet processing (on recv)

	_, ok = packet.TransportLayer().(*layers.TCP)
	if ok {
		packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())
	} else {
		_, ok = packet.TransportLayer().(*layers.UDP)
		if ok {
			packet.TransportLayer().(*layers.UDP).SetNetworkLayerForChecksum(packet.NetworkLayer())
		} else {
			custom_log("Error", "Unsupported TransportLayer type")
			return []byte{}
		}
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializePacket(buffer, opts, packet)
	if err != nil {
		custom_log("Error", "Failed to serialize layers for modified packet: %v", err)
		return []byte{}
	}

	//custom_log("Trace", "vlan_modify_packet_on_recv() after modify:")
	//dump_bytes(buffer.Bytes())

	return buffer.Bytes()
}

func hook_arp_handler(packet gopacket.Packet) bool {
	// simulate peer response
	arp_layer := packet.Layer(layers.LayerTypeARP)
	if arp_layer == nil {
		return false
	}
	arp, _ := arp_layer.(*layers.ARP)
	if arp.Operation != layers.ARPRequest {
		return true
	}

	if !MainProgramConfig.Vlan.CIDR_obj.Contains(arp.DstProtAddress) {
		return true
	}

	if bytes.Equal(arp.DstHwAddress, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		return true
	}

	eth := layers.Ethernet{
		SrcMAC:       MainProgramConfig.Vlan.LocalRealGatewayMAC_obj,
		DstMAC:       MainProgramConfig.Vlan.LocalRealMAC_obj,
		EthernetType: layers.EthernetTypeARP,
	}
	arp_resp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   MainProgramConfig.Vlan.LocalRealGatewayMAC_obj,
		SourceProtAddress: arp.DstProtAddress,
		DstHwAddress:      MainProgramConfig.Vlan.LocalRealMAC_obj,
		DstProtAddress:    MainProgramConfig.Vlan.LocalRealIP_obj,
	}
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, opts, &eth, &arp_resp)
	_ = vlan_netdevice_handle.WritePacketData(buffer.Bytes())
	custom_log("Trace", "Injected ARP response")
	return true
}
