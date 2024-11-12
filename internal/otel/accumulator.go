package otel

import (
	ebpf "eBPF-Golang-telemetry/internal/bpf"
	"log"
	"os"
	"os/signal"
	"time"
)

func AccumulateMetrics() {

	loadEbpf()
	defer unloadEbpf()

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)

	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			accumulateValues()
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		}
	}

}

func accumulateValues() {
	for _, controller := range ebpf.EbpfControllerList {
		log.Println(controller.GetValue())
	}
}

func loadEbpf() {
	for _, controller := range ebpf.EbpfControllerList {
		err := controller.Load()

		if err != nil {
			log.Fatalf("Failed to load eBPF program: %v", err)
		}
	}
}

func unloadEbpf() {
	for _, controller := range ebpf.EbpfControllerList {
		err := controller.Unload()

		if err != nil {
			log.Fatalf("Failed to unload eBPF program: %v", err)
		}
	}
}
