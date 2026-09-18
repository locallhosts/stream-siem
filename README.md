# Stream SIEM

A real-time security telemetry pipeline built around **Go, Apache Kafka, Apache Flink, ClickHouse, and Python**.

The project ingests authentication, DNS, and firewall telemetry; parses it into a common event model; applies stateful, event-time detection; persists enriched events and alerts in ClickHouse; and republishes alerts to Kafka for downstream automation.

![Stream SIEM smoke-test output](docs/images/smoke_test_results.png)

> The screenshot above is from the repository's local smoke test: detector logic was run against generated telemetry and the resulting events and alerts were inserted into a running ClickHouse instance. The load generator uses reserved documentation IP ranges for simulated external destinations.

---

## Architecture

```
                    Synthetic logs / real log sources
                                  |
                                  v
                         +----------------+
                         | Go Forwarder   |
                         | file + syslog  |
                         +-------+--------+
                                 |
                                 v
                    +-------------------------+
                    | Apache Kafka             |
                    | siem.raw.events          |
                    +------------+--------------+
                                 |
                                 v
                    +-------------------------+
                    | Apache Flink             |
                    | event-time processing    |
                    | parsing + detection      |
                    +------------+--------------+
                                 |
                  +--------------+---------------+
                  |                              |
                  v                              v
        +-------------------+          +-------------------+
        | ClickHouse        |          | Kafka             |
        | enriched_events   |          | siem.alerts       |
        | alerts             |          | dead letters      |
        +-------------------+          +-------------------+
```

### Detection pipeline

The Flink job uses the timestamp contained in each log event rather than ingestion time.

1. Kafka provides raw envelopes.
2. Flink parses the source-specific log format.
3. Invalid JSON, unknown source types, and parse failures are sent to a dead-letter topic.
4. Parsed events receive event-time timestamps.
5. Bounded-out-of-orderness watermarks handle out-of-order delivery.
6. Stateful detectors evaluate authentication, firewall, and DNS behavior.
7. Alerts are written to ClickHouse and published to Kafka.
8. Late authentication events that exceed the configured allowed lateness are routed to a dedicated dead-letter stream.

---

## Detection capabilities

### Failed-login rate

Detects repeated authentication failures from a source IP using a **5-minute tumbling event-time window**.

- Key: source IP
- Default threshold: 10 failed logins
- Event-time processing
- Configurable threshold
- Alert score increases with the observed failure count

This detector is intended to identify brute-force-style authentication activity while keeping the implementation inexpensive for high-volume authentication streams.

### Beaconing

Detects repeated outbound connections whose inter-arrival times are unusually regular.

The detector:

- keys state by `sourceIp|destIp`
- keeps a bounded timestamp buffer
- calculates inter-arrival intervals
- calculates the coefficient of variation (CV)
- requires a minimum number of observations
- constrains the average interval to a configurable range
- expires inactive state after 15 minutes
- applies a cooldown so an established beacon does not generate an alert on every event

The important signal is **regularity**, not a specific destination or fixed interval. This makes the detector useful for identifying periodic callback behavior with jitter.

### DNS tunneling

Detects DNS activity whose subdomain entropy is statistically unusual relative to an offline-trained baseline.

The streaming detector:

- keys state by source IP
- calculates Shannon entropy for query labels
- maintains running count, sum, and sum-of-squares
- uses O(1) state per source IP
- evaluates a configurable tumbling window
- calculates a z-score against the trained baseline
- emits an alert when the z-score exceeds the configured threshold

The baseline trainer in `ml-model/` uses a **median + MAD-based robust scale estimate**, which reduces the influence of contaminated training data.

---

## Event-time and late-data handling

The pipeline is deliberately event-time based.

For DNS and firewall logs, timestamps are parsed directly from the RFC3339 event timestamp. Authentication logs use the traditional RFC3164-style timestamp and therefore require a year to be inferred.

Flink uses:

- **30-second bounded out-of-orderness**
- **2-minute source idleness detection**
- **30-second allowed lateness for the failed-login window**
- a dead-letter side output for authentication events that arrive after the allowed-lateness boundary

This means a delayed event is not automatically treated as a new real-time event. Window behavior is driven by the event timestamp and watermark progression.

> **RFC3164 limitation:** traditional syslog authentication timestamps do not contain a year. The current parser uses the current UTC year. Deployments that replay logs across a year boundary should use a source with an explicit year (for example RFC5424) or normalize the timestamp upstream.

---

## Delivery and recovery semantics

Flink checkpointing is configured for **exactly-once state consistency**:

```java
env.enableCheckpointing(30_000, CheckpointingMode.EXACTLY_ONCE);
```

This protects Flink's managed state and Kafka source offsets during recovery.

The external sinks currently have different guarantees:

| Component | Current behavior |
|---|---|
| Flink managed state | Exactly-once checkpoint semantics |
| Kafka alert sink | At-least-once |
| ClickHouse JDBC sink | At-least-once |

A task restart can therefore replay a sink batch. The current ClickHouse schema uses `MergeTree`; it does not implement sink-level deduplication.

For a deployment that requires stronger end-to-end guarantees, the write path would need an explicit idempotency/deduplication strategy or transactional sink design.

---

## Data model

### Parsed event types

The current parsers support:

| Source | Example data |
|---|---|
| `auth` | SSH accepted/failed authentication |
| `dns` | DNS query and source IP |
| `firewall` | ALLOW/DENY, protocol, source, destination, port |

All sources are normalized into the shared `ParsedEvent` model before detection.

### ClickHouse

The `siem` database contains:

- `enriched_events` — normalized security telemetry
- `alerts` — detector output
- `alert_hourly_rollup` — aggregated alert counts and maximum scores
- a materialized view that maintains the hourly alert rollup

The primary sort keys are designed around source type, source IP, and event time for common analyst queries.

Retention is configured in the schema as:

- enriched events: **90 days**
- alerts: **365 days**

Adjust these values for the retention and compliance requirements of the environment where the system is deployed.

---

## Synthetic load generator

The Go load generator produces realistic-looking authentication, DNS, and firewall records at a configurable rate.

It deliberately plants known detection patterns so the pipeline can be tested against ground truth:

- two beaconing sources
- one DNS-tunneling source
- normal authentication failures
- ordinary DNS queries
- ordinary outbound firewall traffic

The generator uses:

```
203.0.113.0/24
198.51.100.0/24
```

for simulated external destinations. These are reserved documentation ranges, so they should not be interpreted as real C2 infrastructure or company-owned addresses.

Example:

```
10.0.6.200  -> 198.51.100.77:443
10.0.6.201  -> 198.51.100.77:443
10.0.7.50   -> high-entropy DNS labels
```

The generator is deterministic by default through a fixed PRNG seed, making repeated test runs easier to compare.

---

## Local development

### Requirements

- Docker and Docker Compose
- Go
- Java 17
- Maven
- Python 3

### 1. Start the infrastructure

From the repository root:

```bash
docker compose up -d
```

This starts:

- Kafka
- ClickHouse
- Flink JobManager
- Flink TaskManagers
- Go forwarder

The load generator is optional and is not started by the default Compose profile.

### 2. Build the Flink job

```bash
cd flink-job
mvn test
mvn package
cd ..
```

The package step produces the fat JAR used by the Flink cluster.

### 3. Submit the Flink job

```bash
docker compose exec flink-jobmanager flink run \
  -c com.siem.jobs.SiemStreamJob \
  /opt/flink/usrlib/siem-flink-job-1.0.0.jar
```

### 4. Generate test telemetry

```bash
docker compose --profile loadgen up loadgen
```

The default load generator runs at 2,000 events/second for 30 minutes.

For a shorter local run, execute the binary directly:

```bash
cd go-forwarder
go run ./cmd/loadgen -rate 1000 -duration 2m -out-dir ./synthetic-logs
```

### 5. Watch the pipeline

Flink Web UI:

```
http://localhost:8081
```

Kafka alert stream:

```bash
docker compose logs -f flink-jobmanager | grep ALERT
```

ClickHouse:

```bash
docker compose exec clickhouse clickhouse-client --database=siem \
  --query "SELECT * FROM alerts ORDER BY detected_at DESC LIMIT 20"
```

---

## Local smoke test

The repository includes `tools/local_pipeline_smoke_test.py`.

It is a fast, single-process validation path for:

- log parser compatibility
- detector behavior
- alert generation
- ClickHouse insertion
- schema compatibility

Example:

```bash
python3 tools/local_pipeline_smoke_test.py \
  --auth-log ./synthetic-logs/auth.log \
  --dns-log ./synthetic-logs/dns.log \
  --firewall-log ./synthetic-logs/firewall.log \
  --model-params ./ml-model/model_params.json \
  --clickhouse-insert
```

The smoke test intentionally mirrors the Java parser and detector logic, but it is **not a replacement for the distributed Flink job**. It does not prove correctness under Kafka partitioning, real watermark progression, task failures, checkpoint recovery, or concurrent execution.

---

## DNS baseline training

The Python model trainer creates the baseline consumed by the Java DNS detector.

```bash
python3 ml-model/train_dns_entropy_model.py \
  --input ./synthetic-logs/dns.log \
  --output ./ml-model/model_params.json
```

Optional tuning parameters include:

```bash
--z-score-threshold
--min-queries-per-window
--window-size-ms
```

The generated JSON is intentionally compatible with `DnsTunnelingModelParams` in the Flink job.

For the synthetic dataset used with this project, the DNS detector required threshold calibration because short hexadecimal labels have a practical entropy ceiling below their theoretical alphabet maximum. The included smoke-test output documents that tuning process rather than hiding the initial false negative.

---

## Go forwarder

The forwarder supports:

- file tailing
- syslog UDP ingestion
- batching
- Kafka delivery
- compression
- configurable retries
- Prometheus-style metrics
- bounded buffering/backpressure

Configuration example:

```yaml
node_id: forwarder-01

kafka:
  brokers:
    - kafka:9092
  topic: siem.raw.events
  batch_size: 500
  batch_timeout: 1s
  compression: snappy
  required_acks: 1
  max_retries: 5
```

For higher durability requirements on a replicated Kafka cluster, configure acknowledgements appropriately for the deployment rather than using the single-node development defaults.

---

## Project structure

```
.
├── clickhouse/
│   ├── schema.sql
│   ├── schema.local-smoke-test.sql
│   └── sample_queries.sql
│
├── flink-job/
│   ├── pom.xml
│   └── src/
│       ├── main/java/com/siem/
│       │   ├── functions/     # Detection operators
│       │   ├── jobs/          # Flink entry point
│       │   ├── model/         # Event, alert and model types
│       │   ├── parse/         # Source parsers
│       │   └── sink/          # Kafka and ClickHouse sinks
│       └── test/
│
├── go-forwarder/
│   ├── cmd/
│   │   ├── forwarder/         # Log shipper
│   │   └── loadgen/           # Synthetic telemetry generator
│   ├── internal/
│   │   ├── config/
│   │   ├── metrics/
│   │   ├── sink/
│   │   └── source/
│   └── config.example.yaml
│
├── ml-model/
│   ├── train_dns_entropy_model.py
│   └── requirements.txt
│
├── tools/
│   ├── local_pipeline_smoke_test.py
│   └── render_smoke_test_results.py
│
├── docs/
│   └── smoke_test_results.png
│
└── docker-compose.yml
```

---

## Testing

The Flink project includes unit tests for the stateful detection components, including:

- beaconing detection
- entropy calculations

Run them with:

```bash
cd flink-job
mvn test
```

The repository also provides the local smoke test for rapid parser/detector/schema validation.

For a full system validation, use Docker Compose and exercise the complete:

```
load generator
    -> Go forwarder
    -> Kafka
    -> Flink
    -> ClickHouse + Kafka alerts
```

---

## Configuration

The Flink job exposes runtime parameters for the main detection controls.

Examples:

```
--kafka-brokers
--raw-topic
--alert-topic
--dead-letter-topic
--consumer-group

--failed-login-threshold

--beacon-max-samples
--beacon-min-samples
--beacon-max-cv
--beacon-min-interval-ms
--beacon-max-interval-ms

--dns-model-path
```

The defaults are intended for the included development environment. Detection thresholds should be calibrated against the actual baseline of the environment being monitored.

---

## Operational considerations

This repository is a development and research implementation rather than a turnkey production deployment.

Before production use, review at least:

- Kafka replication and acknowledgement settings
- TLS and authentication for Kafka
- ClickHouse authentication and network exposure
- Flink checkpoint storage durability
- sink idempotency/deduplication
- schema/version management
- log timestamp normalization
- DNS model training data quality
- detector thresholds and false-positive rates
- dead-letter queue monitoring
- secrets management
- retention and compliance requirements

The Docker Compose configuration intentionally uses a single Kafka broker and development-oriented settings.

---

## Security model and scope

The synthetic traffic in this repository is designed for defensive testing of the detection pipeline.

The project demonstrates **behavioral detection** rather than reputation-based blocking. In particular, a destination IP alone is not treated as malicious. The detectors look for patterns such as:

- repeated authentication failures
- periodic outbound connections
- anomalously high DNS label entropy

This distinction is important when interpreting the synthetic data: the reserved addresses used by the load generator are test infrastructure, not indicators of compromise.

---

## License

See [LICENSE](LICENSE).
