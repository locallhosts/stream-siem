-- LOCAL SMOKE-TEST SCHEMA ONLY. NOT the project deliverable.
--
-- This sandbox has no Docker, so the docker-compose stack (which uses
-- clickhouse/clickhouse-server:24.8, per docker-compose.yml) can't run
-- here. The only way to get a *real* ClickHouse running in this
-- environment is apt's clickhouse-server package, which resolves to
-- 18.16.1 (from 2018) -- see the README's verification log for the exact
-- error this caused against the real clickhouse/schema.sql:
--
--   Code: 62. Syntax error ... TTL toDateTime(event_time) + INTERVAL 90 DAY
--
-- TTL (added in 19.6), DateTime64 (19.x), LowCardinality (19.0), and
-- generateUUIDv4() (20.1) all postdate 18.16 and aren't available. This
-- file drops exactly those four features so the same INSERT statements
-- and analyst queries can run for real against something, while
-- clickhouse/schema.sql -- the actual deliverable -- keeps all of them
-- for the real 24.8 target.

CREATE DATABASE IF NOT EXISTS siem;

CREATE TABLE IF NOT EXISTS siem.enriched_events
(
    event_date    Date MATERIALIZED toDate(event_time),
    event_time    DateTime,
    source_type   String,
    source_ip     String,
    dest_ip       Nullable(String),
    dest_port     Nullable(UInt16),
    user          Nullable(String),
    auth_success  Nullable(UInt8),
    dns_query     Nullable(String),
    host          String,
    raw           String,
    ingested_at   DateTime DEFAULT now()
)
ENGINE = MergeTree(event_date, (source_type, source_ip, event_time), 8192);

CREATE TABLE IF NOT EXISTS siem.alerts
(
    detected_date DATE MATERIALIZED toDate(detected_at),
    detected_at   DateTime,
    window_start  DateTime,
    window_end    DateTime,
    alert_type    String,
    source_type   String,
    source_ip     String,
    dest_ip       Nullable(String),
    score         Float64,
    details       String
)
ENGINE = MergeTree(detected_date, (alert_type, source_ip, detected_at), 8192);
