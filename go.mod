module github.com/Gthulhu/qumun

go 1.24.0

toolchain go1.24.2

require (
	github.com/Gthulhu/plugin v1.0.1
	golang.org/x/sys v0.37.0
)

require github.com/cilium/ebpf v0.20.0

replace github.com/aquasecurity/libbpfgo => ./libbpfgo
