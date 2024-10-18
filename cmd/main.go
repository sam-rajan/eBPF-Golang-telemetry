package main

import (
	"eBPF-Golang-telemetry/internal/ebpf"
	"errors"
	"log"

	eBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

func main() {
	err := features.HaveProgramType(eBPF.XDP)
	if errors.Is(err, eBPF.ErrNotSupported) {
		log.Fatal("eBPF not supported by the Kernel")
	}

	ebpf.Load("eth1")
}
