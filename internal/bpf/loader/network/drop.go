package network

import (
	"eBPF-Golang-telemetry/internal/bpf/network"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type PacketDrops struct {
	TotalPackets int64
}

func (p *PacketDrops) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Failed to remove the resource constraint")
		return err
	}

	var dropPbjects network.PacketDropObjects
	if err := network.LoadPacketDropObjects(&dropPbjects, nil); err != nil {
		log.Println("Failed to load eBPF objects")
		log.Fatal(err)
		return err
	}
	defer dropPbjects.Close()

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
			err := dropPbjects.PktMaps.Lookup(uint32(4), &count)
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
