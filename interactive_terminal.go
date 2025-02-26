package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func iaterm_clog_output_done_hook() {
	fmt.Print("> ")
}

func iaterm_loop() {
	scanner := bufio.NewScanner(os.Stdin)
	clog_println("")
	clog_println("##### Interactive Terminal #####")
	clog_println("Use `help` to view available commands")
	clog_println("")

	for {
		fmt.Print("\r   \r> ")
		if !scanner.Scan() {
			break
		}

		line := scanner.Text()

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "exit":
			os.Exit(0)

		case "help":
			clog_println("===== Command List =====")

			clog_println("`hy2 connect <raddr>`: Connect as a client to <raddr>")
			clog_println("`hy2 serve <laddr>`: Start a server listening on <laddr>")
			clog_println("`hy2 status`: Show the status of the Hy2 service")
			clog_println("`hy2 stop`: Disconnect the client or stop the server")

			clog_println("`vlan netdevice`: List all net devices found")
			clog_println("`vlan start`: Start vlan data copier")

			clog_println("`exit`: Exit program")
			clog_println("`help`: Show this help information")

			clog_println("========================")

		case "vlan":
			if len(parts) < 2 {
				clog_println("Command `vlan` requires at least 1 param")
				continue
			}
			switch parts[1] {
			case "netdevice":
				nli := vlan_list_all_net_device()
				clog_printf("===== Total: %d =====\n", len(nli))
				for _, it := range nli {
					clog_printf("%s %s Flag=%d\n", it.Name, it.Description, it.Flags)
				}
				clog_println("====================")

			default:
				clog_printf("Unknown action `%s`\n", parts[1])
			}

		case "hy2":
			if len(parts) < 2 {
				clog_println("Command `hy2` requires at least 1 param")
				continue
			}
			switch parts[1] {
			case "connect":
				if len(parts) < 3 {
					clog_println("Action `connect` requires at least 1 param")
					continue
				}
				addr := parts[2]
				//go hy2_client_start(addr)
				hy2_client_start(addr)

			case "serve":
				if len(parts) < 3 {
					clog_println("Action `serve` requires at least 1 param")
					continue
				}
				addr := parts[2]
				//go hy2_server_start(addr)
				hy2_server_start(addr)

			case "status":
				if hy2_quic_conn != nil {
					clog_println("hy2_quic_conn is created")
				} else {
					clog_println("hy2_quic_conn is nil")
				}

				if hy2_client_instance != nil {
					clog_println("hy2_client_instance is created")
				} else if hy2_server_instance != nil {
					clog_println("hy2_server_instance is created")
				} else {
					clog_println("hy2_instance NOT found")
				}

			case "stop":
				if hy2_quic_conn != nil {
					(*hy2_quic_conn).CloseWithError(0x010c, "Manual Disconnect") //H3_REQUEST_CANCELLED
					clog_println("hy2_quic_conn closed")
					//hy2_quic_conn = nil
				}
				if hy2_client_instance != nil {
					hy2_client_instance.Close()
					clog_println("hy2_client_instance closed")
					//hy2_client_instance = nil
				}
				if hy2_server_instance != nil {
					hy2_server_instance.Close()
					clog_println("hy2_server_instance closed")
					//hy2_server_instance = nil
				}

			default:
				clog_printf("Unknown action `%s`\n", parts[1])
			}
		default:
			clog_printf("Unknown command `%s`\n", parts[0])
		}
	}
	if err := scanner.Err(); err != nil {
		custom_log("Error", "Stdin closed unexpectly: %v", err)
	}
}
