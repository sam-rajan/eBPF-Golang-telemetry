package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir=network/ --go-package=network PacketSend network/packet/packet_sent.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir=network/ --go-package=network PacketReceive network/packet/packet_receive.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --output-dir=network/ --go-package=network PacketDrop network/packet/packet_drop.bpf.c
