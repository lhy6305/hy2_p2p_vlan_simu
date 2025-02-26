package main

import (
	"time"
)

func vlan_packet_send_worker_set(n int64) {
	cur_worker_count := vlan_packet_send_worker_count.Load()
	for cur_worker_count < n {
		go vlan_packet_send_worker_loop()
		cur_worker_count++
	}
	for cur_worker_count > n {
		vlan_packet_send_worker_cleanup_chan <- struct{}{}
		cur_worker_count--
	}
	go func() {
		time.Sleep(1000 * time.Millisecond)
		if vlan_packet_send_worker_count.Load() != n {
			// whatf?
			custom_log("Logic Error", "vlan_packet_send_worker_count(%d) != n(%d)", vlan_packet_send_worker_count.Load(), n)
		} else {
			custom_log("Info", "vlan_packet_send_worker_count has been set to %d", n)
		}
	}()
}

func vlan_packet_recv1_worker_set(n int64) {
	cur_worker_count := vlan_packet_recv1_worker_count.Load()
	for cur_worker_count < n {
		go vlan_packet_recv1_worker_loop()
		cur_worker_count++
	}
	for cur_worker_count > n {
		vlan_packet_recv1_worker_cleanup_chan <- struct{}{}
		cur_worker_count--
	}
	go func() {
		time.Sleep(1000 * time.Millisecond)
		if vlan_packet_recv1_worker_count.Load() != n {
			// whatf?
			custom_log("Logic Error", "vlan_packet_recv1_worker_count(%d) != n(%d)", vlan_packet_recv1_worker_count.Load(), n)
		} else {
			custom_log("Info", "vlan_packet_recv1_worker_count has been set to %d", n)
		}
	}()
}

func vlan_packet_recv2_worker_set(n int64) {
	cur_worker_count := vlan_packet_recv2_worker_count.Load()
	for cur_worker_count < n {
		go vlan_packet_recv2_worker_loop()
		cur_worker_count++
	}
	for cur_worker_count > n {
		vlan_packet_recv2_worker_cleanup_chan <- struct{}{}
		cur_worker_count--
	}
	go func() {
		time.Sleep(1000 * time.Millisecond)
		if vlan_packet_recv2_worker_count.Load() != n {
			// whatf?
			custom_log("Logic Error", "vlan_packet_recv2_worker_count(%d) != n(%d)", vlan_packet_recv2_worker_count.Load(), n)
		} else {
			custom_log("Info", "vlan_packet_recv2_worker_count has been set to %d", n)
		}
	}()
}
