package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"

	"github.com/locallhosts/siem-forwarder/internal/metrics"
	"github.com/locallhosts/siem-forwarder/internal/source"
)

type KafkaSinkConfig struct {
	Brokers      []string
	Topic        string
	BatchSize    int
	BatchTimeout time.Duration
	Compression  string
	RequiredAcks int
	MaxRetries   int
}

type KafkaSink struct {
	writer *kafka.Writer
	cfg    KafkaSinkConfig
}

func compressionCodec(name string) compress.Compression {
	switch name {
	case "gzip":
		return compress.Gzip
	case "snappy":
		return compress.Snappy
	case "lz4":
		return compress.Lz4
	case "zstd":
		return compress.Zstd
	default:
		return 0 // none
	}
}

func acks(n int) kafka.RequiredAcks {
	switch n {
	case -1:
		return kafka.RequireAll // all in-sync replicas; strongest durability, use for compliance-sensitive sources
	case 0:
		return kafka.RequireNone
	default:
		return kafka.RequireOne
	}
}

func NewKafkaSink(cfg KafkaSinkConfig) *KafkaSink {
	w := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.Hash{}, // hashes on message Key -> same source_type always lands on the same partition, which preserves per-key ordering that the Flink job's KeyedProcessFunction relies on
		BatchSize:    cfg.BatchSize,
		BatchTimeout: cfg.BatchTimeout,
		Compression:  kafka.Compression(compressionCodec(cfg.Compression)),
		RequiredAcks: acks(cfg.RequiredAcks),
		Async:        false, // synchronous WriteMessages gives us a real error to retry on; async would silently drop under backpressure
		ErrorLogger:  kafka.LoggerFunc(func(msg string, args ...interface{}) { log.Printf("[kafka] "+msg, args...) }),
	}
	return &KafkaSink{writer: w, cfg: cfg}
}

func (k *KafkaSink) Close() error {
	return k.writer.Close()
}

// WriteBatch attempts delivery with exponential backoff. It returns an error
// only after exhausting MaxRetries, at which point the caller decides
// whether to drop, spill to disk, or crash-and-let-the-supervisor-restart.
func (k *KafkaSink) WriteBatch(ctx context.Context, events []source.Event) error {
	msgs := make([]kafka.Message, 0, len(events))
	for _, e := range events {
		payload, err := json.Marshal(e)
		if err != nil {
			log.Printf("[kafka] dropping unmarshalable event: %v", err)
			continue
		}
		msgs = append(msgs, kafka.Message{
			Key:   []byte(e.SourceType), // partition key: keeps per-source-type ordering, which the beaconing/tunneling detectors depend on
			Value: payload,
			Time:  e.ReceivedAt,
		})
	}
	if len(msgs) == 0 {
		return nil
	}

	var lastErr error
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt <= k.cfg.MaxRetries; attempt++ {
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := k.writer.WriteMessages(writeCtx, msgs...)
		cancel()
		if err == nil {
			metrics.EventsProduced.Add(float64(len(msgs)))
			return nil
		}
		lastErr = err
		metrics.KafkaWriteErrors.Inc()
		if attempt < k.cfg.MaxRetries {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff *= 2
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
		}
	}
	return fmt.Errorf("kafka write failed after %d attempts: %w", k.cfg.MaxRetries+1, lastErr)
}
