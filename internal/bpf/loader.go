package ebpf

import (
	"eBPF-Golang-telemetry/internal/bpf/metric"
	"errors"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

const (
	unload = iota
	load
)

type ebpfController interface {
	Load() error
	Unload() error
	GetData() []metric.MetricData
}

func handleProgram(operation int) error {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove the resource constraint. Error: ", err.Error())
	}

	log.Println("Loading ebpf programs")
	for _, controller := range ebpfControllerList {
		var err error
		if operation == unload {
			err = controller.Unload()
		} else if operation == load {
			err = controller.Load()
		} else {
			err = errors.New("invalid program operation")
		}

		if err != nil {
			log.Printf("Error loading ebpf program: %s\n", err.Error())
			return err
		}
	}

	return nil
}

func ListenForUpdates(callback func([]metric.MetricData)) {

	err := handleProgram(load)
	if err != nil {
		return
	}

	defer handleProgram(unload)

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)

	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			callback(getMetrics())
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		}
	}

}

func getMetrics() []metric.MetricData {
	var metrics []metric.MetricData
	for _, controller := range ebpfControllerList {
		metrics = append(metrics, controller.GetData()...)
	}

	return metrics
}
