package network

import (
	"log"
	"net"

	"eBPF-Golang-telemetry/internal/bpf/metric"
	network "eBPF-Golang-telemetry/internal/bpf/network"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type PacketSentBytes struct {
	EthInterface string
	link         *link.Link
	ebpfObject   network.PacketSendObjects
}

func (p *PacketSentBytes) Load() error {

	if err := network.LoadPacketSendObjects(&p.ebpfObject, nil); err != nil {
		log.Println("Failed to load eBPF objects")
		return err
	}

	iface, err := net.InterfaceByName(p.EthInterface)
	if err != nil {
		log.Println("Failed to get network interface for inspecting traffic")
		return err
	}

	link, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   p.ebpfObject.TcSentPacket,
		Attach:    ebpf.AttachTCXIngress,
	})

	if err != nil {
		log.Println("Failed to attach eBPF program to interface", err)
		return err
	}
	p.link = &link

	return nil
}

func (p *PacketSentBytes) Unload() error {
	err := (*p.link).Close()

	if err != nil {
		log.Println("Failed to close link")
		return err
	}
	err = p.ebpfObject.Close()

	if err != nil {
		log.Println("Failed to close eBPF objects")
		return err
	}
	log.Println("Unloaded network drop module")
	return nil
}

func (p *PacketSentBytes) GetData() (result []metric.MetricData) {
	result = []metric.MetricData{}

	var packetCount int64
	err := p.ebpfObject.PktMaps.Lookup(int32(2), &packetCount)
	if err != nil {
		log.Println("Failed to read sent packet count from map")
		return
	}

	metric1 := metric.MetricData{
		Name:        "ebpf.network.packets.sent.count",
		Description: "Number of sent network packets detected by eBPF",
		Value:       packetCount,
	}

	result = append(result, metric1)

	var packetReceivedBytes int64
	err = p.ebpfObject.PktMaps.Lookup(int32(3), &packetReceivedBytes)
	if err != nil {
		log.Println("Failed to read sent network bytes from map")
		return
	}

	metric2 := metric.MetricData{
		Name:        "ebpf.network.sent.bytes",
		Description: "Total networks bytes sent detected by eBPF",
		Value:       packetReceivedBytes,
	}

	result = append(result, metric2)

	return
}
