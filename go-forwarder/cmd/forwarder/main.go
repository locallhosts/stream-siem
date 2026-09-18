// Command forwarder is a high-throughput log shipper: it tails files and/or
// listens for syslog UDP, batches events, and produces them to Kafka.
//
// Usage:
//
//	forwarder -config /etc/siem-forwarder/config.yaml
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/locallhosts/siem-forwarder/internal/config"
	"github.com/locallhosts/siem-forwarder/internal/metrics"
	"github.com/locallhosts/siem-forwarder/internal/sink"
	"github.com/locallhosts/siem-forwarder/internal/source"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.Metrics.Enabled {
		go func() {
			log.Printf("metrics listening on %s/metrics", cfg.Metrics.Addr)
			if err := metrics.Serve(cfg.Metrics.Addr); err != nil {
				log.Printf("metrics server stopped: %v", err)
			}
		}()
	}

	// Fan-in channel: every source writes here, one batching consumer drains it.
	// A bounded channel gives us real backpressure — if Kafka is slow, sources
	// block on send rather than the process growing unbounded memory.
	events := make(chan source.Event, 10_000)
	errs := make(chan error, 100)
	sourceStop := make(chan struct{})

	var sources []source.Source
	for _, sc := range cfg.Sources {
		switch sc.Type {
		case "file":
			sources = append(sources, &source.FileSource{
				Path:          sc.Path,
				SourceTypeTag: sc.SourceType,
				NodeID:        cfg.NodeID,
				FromBeginning: sc.FromBeginning,
			})
		case "syslog_udp":
			sources = append(sources, &source.SyslogUDPSource{
				ListenAddr:    sc.ListenAddr,
				SourceTypeTag: sc.SourceType,
				NodeID:        cfg.NodeID,
			})
		}
	}

	for _, s := range sources {
		s := s
		go func() {
			log.Printf("starting source %s", s.Name())
			s.Run(events, errs, sourceStop)
			log.Printf("source %s stopped", s.Name())
		}()
	}

	go func() {
		for err := range errs {
			log.Printf("[source error] %v", err)
		}
	}()

	kafkaSink := sink.NewKafkaSink(sink.KafkaSinkConfig{
		Brokers:      cfg.Kafka.Brokers,
		Topic:        cfg.Kafka.Topic,
		BatchSize:    cfg.Kafka.BatchSize,
		BatchTimeout: cfg.BatchTimeout(),
		Compression:  cfg.Kafka.Compression,
		RequiredAcks: cfg.Kafka.RequiredAcks,
		MaxRetries:   cfg.Kafka.MaxRetries,
	})
	defer kafkaSink.Close()

	runBatcher(ctx, cfg, events, kafkaSink)

	log.Println("shutting down: stopping sources")
	close(sourceStop)
	// Give in-flight sources a moment to notice stop and return.
	time.Sleep(200 * time.Millisecond)
	log.Println("shutdown complete")
	os.Exit(0)
}

// runBatcher drains the events channel into size- or time-bounded batches
// and flushes each to Kafka. It returns when ctx is cancelled, after
// flushing whatever is left in the current batch.
func runBatcher(ctx context.Context, cfg *config.Config, events <-chan source.Event, kafkaSink *sink.KafkaSink) {
	batch := make([]source.Event, 0, cfg.Kafka.BatchSize)
	ticker := time.NewTicker(cfg.BatchTimeout())
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		metrics.QueueDepth.Set(float64(len(events)))
		writeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := kafkaSink.WriteBatch(writeCtx, batch); err != nil {
			log.Printf("[fatal-ish] dropping batch of %d events after retries exhausted: %v", len(batch), err)
			metrics.EventsDropped.Add(float64(len(batch)))
		}
		cancel()
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev := <-events:
			metrics.EventsIngested.Inc()
			batch = append(batch, ev)
			if len(batch) >= cfg.Kafka.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
