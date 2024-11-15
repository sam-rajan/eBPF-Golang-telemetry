package ebpf

import (
	"eBPF-Golang-telemetry/internal/bpf/loader/network"
	"os"
)

var ebpfControllerList = []ebpfController{
	&network.PacketDrops{},
	&network.PacketReceiveBytes{EthInterface: os.Getenv("NET_INTERFACE")},
	&network.PacketSentBytes{EthInterface: os.Getenv("NET_INTERFACE")},
}
