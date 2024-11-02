package network

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	network "eBPF-Golang-telemetry/internal/bpf/network"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type PacketSentBytes struct {
	EthInterface string
	TotalBytes   int64
}

func (p *PacketSentBytes) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Failed to remove the resource constraint")
		return err
	}

	var bytesObjects network.PacketSendObjects
	if err := network.LoadPacketSendObjects(&bytesObjects, nil); err != nil {
		log.Println("Failed to load eBPF objects")
		return err
	}
	defer bytesObjects.Close()

	iface, err := net.InterfaceByName(p.EthInterface)
	if err != nil {
		log.Println("Failed to get network interface for inspecting traffic")
		return err
	}

	link, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   bytesObjects.TcSentPacket,
		Attach:    ebpf.AttachTCXIngress,
	})

	if err != nil {
		log.Println("Failed to attach eBPF program to interface", err)
		return err
	}
	defer link.Close()

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)

	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			var count uint64
			err := bytesObjects.PktMaps.Lookup(uint32(3), &count)
			if err != nil {
				log.Fatal("Failed to lookup packet bytes Error:", err)
			}

			log.Printf("Total Size of packets sent: %d", count)
		case <-stop:
			log.Println("Received signal, exiting...")
			return nil
		}
	}
}
