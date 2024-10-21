package main

import (
	network "eBPF-Golang-telemetry/internal/bpf/network/packet"
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

	var packetSize = &network.PacketDrops{
		EthInterface: "wlp2s0",
	}
	packetSize.Load()
}
