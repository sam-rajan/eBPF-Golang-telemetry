package ebpf

import "eBPF-Golang-telemetry/internal/bpf/loader/network"

var ebpfControllerList = []ebpfController{
	&network.PacketDrops{},
	&network.PacketReceiveBytes{EthInterface: "wlp2s0"},
	&network.PacketSentBytes{EthInterface: "wlp2s0"},
}
