module github.com/yourorg/siem-forwarder

go 1.22

require (
	github.com/prometheus/client_golang v1.19.1
	github.com/segmentio/kafka-go v0.4.47
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

// Vanity import paths (golang.org/x/..., gopkg.in/...) resolve via an HTTP
// go-get meta tag lookup against the vanity host itself. In network
// environments that only allowlist github.com (e.g. this sandbox's build),
// that lookup fails even with GOPROXY=direct. These replaces point straight
// at the same code's GitHub mirror so `go mod tidy`/`go build` work without
// a module proxy. Safe to delete once you have proxy.golang.org (the
// default GOPROXY) or general internet egress.
replace (
	golang.org/x/crypto => github.com/golang/crypto v0.14.0
	golang.org/x/mod => github.com/golang/mod v0.8.0
	golang.org/x/net => github.com/golang/net v0.17.0
	golang.org/x/sync => github.com/golang/sync v0.4.0
	golang.org/x/sys => github.com/golang/sys v0.13.0
	golang.org/x/term => github.com/golang/term v0.13.0
	golang.org/x/text => github.com/golang/text v0.13.0
	golang.org/x/tools => github.com/golang/tools v0.6.0
	golang.org/x/xerrors => github.com/golang/xerrors v0.0.0-20220907171357-04be3eba64a2
	google.golang.org/protobuf => github.com/protocolbuffers/protobuf-go v1.33.0
	gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20201130134442-10cb98267c6c
	gopkg.in/yaml.v3 => github.com/go-yaml/yaml v0.0.0-20250401170010-944c86a7d293
)
