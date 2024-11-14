package otel

import (
	"context"
	ebpf "eBPF-Golang-telemetry/internal/bpf"
	ebpfMetric "eBPF-Golang-telemetry/internal/bpf/metric"
	"log"
	"os"

	opentelemetry "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var meter = opentelemetry.Meter("ebpf-telemetry")
var counterMap = map[string]metric.Int64Counter{}
var guageMap = map[string]metric.Int64Gauge{}
var hostname, _ = os.Hostname()

func CollectMetrics() {

	log.Println("Starting metrics collector")
	ebpf.ListenForUpdates(func(md []ebpfMetric.MetricData) {
		for _, metricData := range md {
			if metricData.Type == ebpfMetric.Gauge {
				updateGaugeMetric(metricData)
			} else if metricData.Type == ebpfMetric.Counter {
				updateCounterMetric(metricData)
			}
		}
	})

}

func updateCounterMetric(metricData ebpfMetric.MetricData) {
	counter, ok := counterMap[metricData.Name]
	if !ok {
		counter, _ = meter.Int64Counter(metricData.Name,
			metric.WithDescription(metricData.Description), metric.WithUnit(metricData.Unit))
		counterMap[metricData.Name] = counter
	}
	counter.Add(context.Background(), 1, metric.WithAttributes(
		attribute.Int64("value", metricData.Value),
		attribute.String("host", hostname),
	))
}

func updateGaugeMetric(metricData ebpfMetric.MetricData) {
	guage, ok := guageMap[metricData.Name]
	if !ok {
		guage, _ = meter.Int64Gauge(metricData.Name,
			metric.WithDescription(metricData.Description), metric.WithUnit(metricData.Unit))
		guageMap[metricData.Name] = guage
	}
	guage.Record(context.Background(), 1, metric.WithAttributes(
		attribute.Int64("value", metricData.Value),
		attribute.String("host", hostname),
	))
}
