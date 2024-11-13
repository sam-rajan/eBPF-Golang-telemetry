package otel

import (
	"context"
	ebpf "eBPF-Golang-telemetry/internal/bpf"
	"log"
	"os"
	"os/signal"
	"time"

	opentelemetry "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var meter = opentelemetry.Meter("eBPF-Golang-telemetry")
var counterMap = map[string]metric.Int64Counter{}

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
		value, _ := controller.GetValue()
		valueAttr := attribute.Int64("value", value)

		counterMap[controller.GetName()].Add(context.Background(), 1,
			metric.WithAttributes(valueAttr))
	}
}

func loadEbpf() {
	for _, controller := range ebpf.EbpfControllerList {

		counterMap[controller.GetName()], _ = meter.Int64Counter(controller.GetName())
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
