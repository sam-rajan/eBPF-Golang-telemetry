package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir=network/packet/ --go-package=network PacketCounter network/packet/packet_counter.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir=network/packet/ --go-package=network PacketBytes network/packet/packet_bytes.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir=network/packet/ --go-package=network PacketDrop network/packet/packet_drop.c
