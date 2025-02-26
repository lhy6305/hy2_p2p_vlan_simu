package main

import (
	"os"
)

func main() {
	config_init1()
	config_init2()
	config_init3()

	if err := windows_SetPriority(os.Getpid(), 128); err != nil {
		custom_log("Error", "Failed to call SetPriority: %v", err)
	}
	custom_log("Info", "Set self priority to High Priority")

	framepool_init()
	go framepool_time_based_cleanup_loop()

	go vlan_data_copier2_worker_loop()

	if MainProgramConfig.Vlan.ParamCheckOK {
		vlan_open_netdevice()
		vlan_packet_send_worker_set(MainProgramConfig.Vlan.PacketSendThreadCount)
		vlan_packet_recv1_worker_set(MainProgramConfig.Vlan.PacketRecv1ThreadCount)
		vlan_packet_recv2_worker_set(MainProgramConfig.Vlan.PacketRecv2ThreadCount)
	} else {
		custom_log("Error", "Vlan.ParamCheckOK is false. You may have provided invalid parameters")
	}

	go iaterm_loop()

	select {}
}
