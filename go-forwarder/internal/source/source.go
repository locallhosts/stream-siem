package source

import "time"

// Event is the normalized envelope produced by every source before it hits
// Kafka. Keeping this narrow and stable is what lets the Flink job assume a
// consistent schema regardless of which forwarder or collector produced it.
type Event struct {
	SourceType string    `json:"source_type"` // "auth", "dns", "firewall", "http", ...
	Host       string    `json:"host"`        // node_id of the forwarder that observed it
	ReceivedAt time.Time `json:"received_at"` // wall clock at the forwarder (used for lag metrics only)
	Raw        string    `json:"raw"`         // unparsed original line; Flink does structured parsing per source_type
}

// Source produces Events onto the given channel until ctx is cancelled or
// the underlying source is exhausted/errors. It must close outCh's producer
// side responsibilities by simply returning; the caller owns the channel.
type Source interface {
	Run(out chan<- Event, errs chan<- error, stop <-chan struct{})
	Name() string
}
