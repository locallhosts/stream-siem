package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	EventsIngested = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_forwarder_events_ingested_total",
		Help: "Events read from sources before batching/production.",
	})
	EventsProduced = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_forwarder_events_produced_total",
		Help: "Events successfully written to Kafka.",
	})
	EventsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_forwarder_events_dropped_total",
		Help: "Events dropped after exhausting retries.",
	})
	KafkaWriteErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "siem_forwarder_kafka_write_errors_total",
		Help: "Failed Kafka WriteMessages attempts (including ones later retried successfully).",
	})
	QueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "siem_forwarder_queue_depth",
		Help: "Current depth of the internal event channel between sources and the Kafka sink.",
	})
)

// Serve starts a blocking HTTP server exposing /metrics on addr.
// Call this in its own goroutine.
func Serve(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	return http.ListenAndServe(addr, mux)
}
