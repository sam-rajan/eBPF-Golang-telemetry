package network

import (
	"eBPF-Golang-telemetry/internal/bpf/metric"
	"eBPF-Golang-telemetry/internal/bpf/network"
	"log"

	"github.com/cilium/ebpf/link"
)

type PacketDrops struct {
	ebpfObject network.PacketDropObjects
	link       *link.Link
}

func (p *PacketDrops) Load() error {

	if err := network.LoadPacketDropObjects(&p.ebpfObject, nil); err != nil {
		log.Println("Failed to load eBPF objects")
		log.Fatal(err)
		return err
	}

	link, err := link.Tracepoint("skb", "kfree_skb", p.ebpfObject.CountPacketDrops, nil)
	p.link = &link
	if err != nil {
		log.Println("Failed to link Tracepoint program")
		return err
	}

	return nil
}

func (p *PacketDrops) Unload() error {
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

func (p *PacketDrops) GetData() (result []metric.MetricData) {
	result = []metric.MetricData{}

	var value int64
	err := p.ebpfObject.PktMaps.Lookup(int32(4), &value)
	if err != nil {
		log.Println("Failed to read network drop value from map")
		return
	}

	data := metric.MetricData{
		Name:        "ebpf.network.packets.count",
		Description: "Number of network packets detected by eBPF",
		Value:       value,
	}

	result = append(result, data)
	return
}
