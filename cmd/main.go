package main

import (
	"context"
	"errors"
	"log"

	"eBPF-Golang-telemetry/internal/otel"

	eBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

func main() {
	log.Println("Starting eBPF-Golang-telemetry")
	err := features.HaveProgramType(eBPF.XDP)
	if errors.Is(err, eBPF.ErrNotSupported) {
		log.Fatal("eBPF not supported by the Kernel")
	}

	log.Println("eBPF supported by the Kernel")

	otelShutdown, err := otel.SetupOtel(context.Background())
	if err != nil {
		log.Fatalf("Failed to setup otel. Reason : %s", err.Error())
	}
	// Handle shutdown properly so nothing leaks.
	defer func() {
		log.Println("Shutting down eBPF-Golang-telemetry")
		err = errors.Join(err, otelShutdown(context.Background()))
	}()

	otel.CollectMetrics()
}
