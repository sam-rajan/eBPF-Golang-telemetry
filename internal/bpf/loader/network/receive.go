package network

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	network "eBPF-Golang-telemetry/internal/bpf/network"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type PacketReceiveBytes struct {
	EthInterface string
	TotalBytes   int64
}

func (p *PacketReceiveBytes) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Failed to remove the resource constraint")
		return err
	}

	var bytesObjects network.PacketReceiveObjects
	if err := network.LoadPacketReceiveObjects(&bytesObjects, nil); err != nil {
		log.Println("Failed to load eBPF objects")
		return err
	}
	defer bytesObjects.Close()

	iface, err := net.InterfaceByName(p.EthInterface)
	if err != nil {
		log.Println("Failed to get network interface for inspecting traffic")
		return err
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Interface: iface.Index,
		Program:   bytesObjects.XdpRecievedPacket,
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
			err := bytesObjects.PktMaps.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Failed to lookup packet bytes Error:", err)
			}

			log.Printf("Total Size of packets received: %d", count)
		case <-stop:
			log.Println("Received signal, exiting...")
			return nil
		}
	}
}
