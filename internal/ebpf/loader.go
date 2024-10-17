package ebpf

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func Load(networkInterface string) {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove the resource constraint Error:", err)
	}

	var counterObjs nwpktcounterObjects
	if err := loadNwpktcounterObjects(&counterObjs, nil); err != nil {
		log.Fatal("Failed to load nwpktcounterObjects Error:", err)
	}
	defer counterObjs.Close()

	iface, err := net.InterfaceByName(networkInterface)
	if err != nil {
		log.Fatal("Failed to get network interface Error:", err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   counterObjs.XdpProg,
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
