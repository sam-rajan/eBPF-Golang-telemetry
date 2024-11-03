package main

import (
	"context"
	"errors"
	"log"
	"net/http"

	"eBPF-Golang-telemetry/internal/otel"

	eBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

func main() {
	err := features.HaveProgramType(eBPF.XDP)
	if errors.Is(err, eBPF.ErrNotSupported) {
		log.Fatal("eBPF not supported by the Kernel")
	}

	otelShutdown, err := otel.SetupOtel(context.Background())
	if err != nil {
		log.Fatalf("Failed to setup otel. Reason : %s", err.Error())
	}
	// Handle shutdown properly so nothing leaks.
	defer func() {
		err = errors.Join(err, otelShutdown(context.Background()))
	}()

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	err = http.ListenAndServe(":9000", nil)

	if err != nil {
		log.Fatal(err)
	}
}
