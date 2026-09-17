-- SIEM ClickHouse schema.
--
-- Design notes:
-- * MergeTree with (source_type, source_ip, event_time) as the primary key
--   / sort key: analyst queries almost always filter or group by source_ip
--   within a source_type and a time range, so ClickHouse can skip whole
--   granules instead of scanning the full table.
-- * PARTITION BY toYYYYMM(event_time): keeps individual parts a manageable
--   size and makes retention trivial (`ALTER TABLE ... DROP PARTITION`
--   instead of a slow row-by-row DELETE).
-- * TTL on both tables: raw enriched events are high-volume/lower-value
--   after 90 days; alerts (much lower volume, higher value) are kept a
--   year. Adjust to your actual retention/compliance requirements.

CREATE DATABASE IF NOT EXISTS siem;

CREATE TABLE IF NOT EXISTS siem.enriched_events
(
    event_time    DateTime64(3),
    source_type   LowCardinality(String),
    source_ip     String,
    dest_ip       Nullable(String),
    dest_port     Nullable(UInt16),
    user          Nullable(String),
    auth_success  Nullable(UInt8),
    dns_query     Nullable(String),
    host          String,
    raw           String,
    ingested_at   DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (source_type, source_ip, event_time)
TTL toDateTime(event_time) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.alerts
(
    detected_at   DateTime64(3),
    window_start  DateTime64(3),
    window_end    DateTime64(3),
    alert_type    LowCardinality(String),
    source_type   LowCardinality(String),
    source_ip     String,
    dest_ip       Nullable(String),
    score         Float64,
    details       String,
    alert_id      UUID DEFAULT generateUUIDv4()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(detected_at)
ORDER BY (alert_type, source_ip, detected_at)
TTL toDateTime(detected_at) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- Materialized view: per-source_ip, per-hour rollup of alert counts by type.
-- Powers a "top noisy sources this week" dashboard panel without scanning
-- siem.alerts directly every time it loads.
CREATE TABLE IF NOT EXISTS siem.alert_hourly_rollup
(
    hour        DateTime,
    alert_type  LowCardinality(String),
    source_ip   String,
    alert_count AggregateFunction(count, UInt64),
    max_score   AggregateFunction(max, Float64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (alert_type, source_ip, hour);

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.alert_hourly_rollup_mv
TO siem.alert_hourly_rollup
AS
SELECT
    toStartOfHour(detected_at) AS hour,
    alert_type,
    source_ip,
    countState() AS alert_count,
    maxState(score) AS max_score
FROM siem.alerts
GROUP BY hour, alert_type, source_ip;
