package network

import (
	"log"
	"net"

	"eBPF-Golang-telemetry/internal/bpf/metric"
	network "eBPF-Golang-telemetry/internal/bpf/network"

	"github.com/cilium/ebpf/link"
)

type PacketReceiveBytes struct {
	EthInterface string
	link         *link.Link
	ebpfObject   network.PacketReceiveObjects
}

func (p *PacketReceiveBytes) Load() error {

	if err := network.LoadPacketReceiveObjects(&p.ebpfObject, nil); err != nil {
		log.Println("Failed to load eBPF objects")
		return err
	}

	iface, err := net.InterfaceByName(p.EthInterface)
	if err != nil {
		log.Println("Failed to get network interface for inspecting traffic")
		return err
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Interface: iface.Index,
		Program:   p.ebpfObject.XdpRecievedPacket,
	})

	if err != nil {
		log.Println("Failed to attach eBPF program to interface", err)
		return err
	}
	p.link = &link

	return nil
}

func (p *PacketReceiveBytes) Unload() error {
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

func (p *PacketReceiveBytes) GetData() (result []metric.MetricData) {
	result = []metric.MetricData{}

	var packetCount int64
	err := p.ebpfObject.PktMaps.Lookup(int32(0), &packetCount)
	if err != nil {
		log.Println("Failed to read received packet count from map")
		return
	}

	metric1 := metric.MetricData{
		Name:        "ebpf.network.packets.received.count",
		Description: "Number of received network packets detected by eBPF",
		Value:       packetCount,
		Unit:        "{packets}",
		Type:        metric.Counter,
	}

	result = append(result, metric1)

	var packetReceivedBytes int64
	err = p.ebpfObject.PktMaps.Lookup(int32(1), &packetReceivedBytes)
	if err != nil {
		log.Println("Failed to read network received bytes from map")
		return
	}

	metric2 := metric.MetricData{
		Name:        "ebpf.network.received.bytes",
		Description: "Total networks bytes received detected by eBPF",
		Value:       packetReceivedBytes,
		Unit:        "By",
		Type:        metric.Counter,
	}

	result = append(result, metric2)

	return
}
