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

type PacketCount struct {
	EthInterface string
	TotalPackets int64
}

func (p *PacketCount) Load() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove the resource constraint Error:", err)
	}

	var counterObjs PacketCounterObjects
	if err := LoadPacketCounterObjects(&counterObjs, nil); err != nil {
		log.Fatal("Failed to load nwpktcounterObjects Error:", err)
	}
	defer counterObjs.Close()

	iface, err := net.InterfaceByName(p.EthInterface)
	if err != nil {
		log.Fatal("Failed to get network interface Error:", err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   counterObjs.XdpPacketCounter,
		Interface: iface.Index,
	})

	if err != nil {
		log.Fatal("Failed to attach XDP program to interface Error:", err)
	}
	defer link.Close()

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)

	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			var count uint64
			err := counterObjs.PktCountMap.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Failed to lookup packet count Error:", err)
			}

			log.Printf("Number of packets received: %d", count)
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		}
	}
}
