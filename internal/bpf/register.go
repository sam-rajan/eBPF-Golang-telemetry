package ebpf

import "eBPF-Golang-telemetry/internal/bpf/loader/network"

var EbpfControllerList = []EbpfController{
	&network.PacketDrops{},
}
