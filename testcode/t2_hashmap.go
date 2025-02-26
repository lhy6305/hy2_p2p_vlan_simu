package main

import (
	"fmt"
)

func main2() {
	ipToMac := make(map[string][]byte)

	ip1 := []byte{192, 168, 1, 1}
	mac1 := []byte{0x00, 0x14, 0x22, 0x01, 0x23, 0x45}
	ipToMac[string(ip1)] = mac1

	ip2 := []byte{192, 168, 1, 2}
	mac2 := []byte{0x00, 0x14, 0x22, 0x01, 0x23, 0x46}
	ipToMac[string(ip2)] = mac2

	queryIP := []byte{192, 168, 1, 1}
	mac, found := ipToMac[string(queryIP)]
	if found {
		fmt.Printf("IP %v 对应的 MAC 地址是 %v\n", queryIP, mac)
	} else {
		fmt.Println("未找到对应的 MAC 地址")
	}
}
