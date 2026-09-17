package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level forwarder configuration, loaded from YAML and
// overridable via environment variables (see applyEnvOverrides).
type Config struct {
	NodeID string `yaml:"node_id"`

	Kafka struct {
		Brokers      []string `yaml:"brokers"`
		Topic        string   `yaml:"topic"`
		BatchSize    int      `yaml:"batch_size"`
		BatchTimeout duration `yaml:"batch_timeout"`
		Compression  string   `yaml:"compression"` // none|gzip|snappy|lz4|zstd
		RequiredAcks int      `yaml:"required_acks"`
		MaxRetries   int      `yaml:"max_retries"`
	} `yaml:"kafka"`

	Sources []SourceConfig `yaml:"sources"`

	Metrics struct {
		Enabled bool   `yaml:"enabled"`
		Addr    string `yaml:"addr"`
	} `yaml:"metrics"`
}

// SourceConfig describes one ingestion source. Type determines which
// fields are relevant: "file" uses Path/SourceType, "syslog_udp" uses
// ListenAddr/SourceType.
type SourceConfig struct {
	Type       string `yaml:"type"` // file | syslog_udp
	SourceType string `yaml:"source_type"` // logical label used for Kafka partition key, e.g. "auth", "dns", "firewall"
	Path       string `yaml:"path,omitempty"`
	ListenAddr string `yaml:"listen_addr,omitempty"`
	FromBeginning bool `yaml:"from_beginning,omitempty"`
}

// duration wraps time.Duration so it can be parsed from YAML strings like "5s".
type duration struct {
	time.Duration
}

func (d *duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = parsed
	return nil
}

func (c *Config) BatchTimeout() time.Duration {
	return c.Kafka.BatchTimeout.Duration
}

// Load reads and validates a YAML config file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func applyDefaults(c *Config) {
	if c.Kafka.BatchSize == 0 {
		c.Kafka.BatchSize = 500
	}
	if c.Kafka.BatchTimeout.Duration == 0 {
		c.Kafka.BatchTimeout.Duration = 1 * time.Second
	}
	if c.Kafka.Compression == "" {
		c.Kafka.Compression = "snappy"
	}
	if c.Kafka.RequiredAcks == 0 {
		c.Kafka.RequiredAcks = 1 // leader ack; set -1 for all-ISR durability
	}
	if c.Kafka.MaxRetries == 0 {
		c.Kafka.MaxRetries = 5
	}
	if c.Metrics.Addr == "" {
		c.Metrics.Addr = ":9109"
	}
	if c.NodeID == "" {
		hostname, _ := os.Hostname()
		c.NodeID = hostname
	}
}

func validate(c *Config) error {
	if len(c.Kafka.Brokers) == 0 {
		return fmt.Errorf("kafka.brokers must not be empty")
	}
	if c.Kafka.Topic == "" {
		return fmt.Errorf("kafka.topic must be set")
	}
	if len(c.Sources) == 0 {
		return fmt.Errorf("at least one source must be configured")
	}
	for i, s := range c.Sources {
		switch s.Type {
		case "file":
			if s.Path == "" {
				return fmt.Errorf("sources[%d]: file source requires path", i)
			}
		case "syslog_udp":
			if s.ListenAddr == "" {
				return fmt.Errorf("sources[%d]: syslog_udp source requires listen_addr", i)
			}
		default:
			return fmt.Errorf("sources[%d]: unknown type %q", i, s.Type)
		}
		if s.SourceType == "" {
			return fmt.Errorf("sources[%d]: source_type must be set (used as Kafka partition key)", i)
		}
	}
	return nil
}
