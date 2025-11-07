module github.com/Gthulhu/qumun

go 1.22.6

require (
	github.com/Gthulhu/plugin v1.0.1
	github.com/aquasecurity/libbpfgo v0.8.0-libbpf-1.5
	golang.org/x/sys v0.26.0
)

replace github.com/aquasecurity/libbpfgo => ./libbpfgo
