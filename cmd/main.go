package main

import "eBPF-Golang-telemetry/internal/ebpf"

func main() {
	ebpf.Load("eth1")
}
