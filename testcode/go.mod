module ly65/ptest

go 1.23.3

require (
	github.com/apernet/hysteria/core/v2 v2.0.0-401ed52
	github.com/apernet/quic-go v0.49.1-0.20250204013113-43c72b1281a0
	github.com/fatih/color v1.18.0
	github.com/google/gopacket v1.1.19
)

replace github.com/apernet/hysteria/core/v2 v2.0.0-401ed52 => ./hysteria-401ed52-core/

require (
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20230131232505-5a9e8f65f08f // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	go.uber.org/mock v0.5.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
)
