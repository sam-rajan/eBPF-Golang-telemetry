package network

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type PacketBytes struct {
	EthInterface string
	TotalBytes   int64
}

func (p *PacketBytes) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Failed to remove the resource constraint")
		return err
	}

	var bytesObjects PacketBytesObjects
	if err := LoadPacketBytesObjects(&bytesObjects, nil); err != nil {
		log.Println("Failed to load eBPF objects")
		return err
	}
	defer bytesObjects.Close()

	iface, err := net.InterfaceByName(p.EthInterface)
	if err != nil {
		log.Println("Failed to get network interface for getting traffic bytes")
		return err
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   bytesObjects.XdpPacketBytes,
		Interface: iface.Index,
	})

	if err != nil {
		log.Println("Failed to attach XDP program to interface")
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
			err := bytesObjects.PktBytesMap.Lookup(uint32(0), &count)
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
