-- Sample ad-hoc analyst queries. Run against a ClickHouse instance loaded
-- with real traffic volume (see ml-model/ and the loadgen tool for
-- generating a multi-million-row synthetic dataset to benchmark against).

-- 1. Top 20 noisiest alerting sources in the last 24 hours.
SELECT
    source_ip,
    alert_type,
    count() AS alert_count,
    max(score) AS max_score,
    min(detected_at) AS first_seen,
    max(detected_at) AS last_seen
FROM siem.alerts
WHERE detected_at >= now() - INTERVAL 1 DAY
GROUP BY source_ip, alert_type
ORDER BY alert_count DESC
LIMIT 20;

-- 2. Failed-login rate over time for a specific source IP (for an analyst
--    drilling into a single alert).
SELECT
    toStartOfFiveMinutes(event_time) AS bucket,
    countIf(auth_success = 0) AS failed,
    countIf(auth_success = 1) AS succeeded
FROM siem.enriched_events
WHERE source_type = 'auth'
  AND source_ip = '10.0.6.200'
  AND event_time >= now() - INTERVAL 6 HOUR
GROUP BY bucket
ORDER BY bucket;

-- 3. All raw context for one beaconing alert's channel: every firewall
--    connection between the flagged source/dest pair, so an analyst can
--    eyeball the actual interval regularity that triggered the alert.
SELECT event_time, dest_ip, dest_port, raw
FROM siem.enriched_events
WHERE source_type = 'firewall'
  AND source_ip = '10.0.6.200'
  AND dest_ip = '198.51.100.77'
ORDER BY event_time
LIMIT 200;

-- 4. DNS query volume and distinct-domain count per source, to eyeball
--    tunneling-adjacent hosts even below the alerting threshold.
SELECT
    source_ip,
    count() AS query_count,
    uniqExact(dns_query) AS distinct_queries,
    round(avg(length(dns_query)), 1) AS avg_query_len
FROM siem.enriched_events
WHERE source_type = 'dns'
  AND event_time >= now() - INTERVAL 1 HOUR
GROUP BY source_ip
ORDER BY query_count DESC
LIMIT 20;

-- 5. Using the pre-aggregated rollup for a fast weekly dashboard panel
--    (reads AggregatingMergeTree state instead of scanning siem.alerts).
SELECT
    hour,
    alert_type,
    countMerge(alert_count) AS alerts,
    maxMerge(max_score) AS peak_score
FROM siem.alert_hourly_rollup
WHERE hour >= now() - INTERVAL 7 DAY
GROUP BY hour, alert_type
ORDER BY hour;

-- 6. Sanity-check ingestion lag: how far behind wall-clock is the pipeline
--    landing events in ClickHouse right now?
SELECT
    source_type,
    quantile(0.5)(dateDiff('second', event_time, ingested_at)) AS p50_lag_seconds,
    quantile(0.99)(dateDiff('second', event_time, ingested_at)) AS p99_lag_seconds
FROM siem.enriched_events
WHERE ingested_at >= now() - INTERVAL 10 MINUTE
GROUP BY source_type;
