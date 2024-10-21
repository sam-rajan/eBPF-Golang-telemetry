package network

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type PacketDrops struct {
	EthInterface string
	TotalPackets int64
}

func (p *PacketDrops) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Failed to remove the resource constraint")
		return err
	}

	var dropPbjects PacketDropObjects
	if err := LoadPacketDropObjects(&dropPbjects, nil); err != nil {
		log.Println("Failed to load eBPF objects")
		log.Fatal(err)
		return err
	}
	defer dropPbjects.Close()

	// iface, err := net.InterfaceByName(p.EthInterface)
	// if err != nil {
	// 	log.Println("Failed to get network interface for getting dropped packet counts")
	// 	return err
	// }

	link, err := link.Tracepoint("skb", "kfree_skb", dropPbjects.CountPacketDrops, nil)

	if err != nil {
		log.Println("Failed to link Tracepoint program")
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
			err := dropPbjects.DropCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Println("Failed to lookup packet count")
				return err
			}

			log.Printf("Number of packets dropped: %d", count)
		case <-stop:
			log.Println("Received signal, exiting...")
			return nil
		}
	}
}
