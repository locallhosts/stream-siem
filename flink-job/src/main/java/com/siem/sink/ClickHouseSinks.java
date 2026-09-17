package com.siem.sink;

import com.siem.model.Alert;
import com.siem.model.ParsedEvent;
import org.apache.flink.connector.jdbc.JdbcConnectionOptions;
import org.apache.flink.connector.jdbc.JdbcExecutionOptions;
import org.apache.flink.connector.jdbc.JdbcSink;
import org.apache.flink.connector.jdbc.JdbcStatementBuilder;
import org.apache.flink.streaming.api.functions.sink.SinkFunction;

import java.sql.Timestamp;

/**
 * Both sinks batch (JdbcExecutionOptions) rather than executing one INSERT
 * per row — ClickHouse is optimized for large-batch inserts and performs
 * badly under row-at-a-time INSERT load, which is the single most common
 * mistake when wiring a stream processor to it.
 */
public final class ClickHouseSinks {

    private ClickHouseSinks() {}

    public static SinkFunction<ParsedEvent> enrichedEventsSink(String jdbcUrl, String user, String password) {
        String sql = "INSERT INTO siem.enriched_events " +
                "(event_time, source_type, source_ip, dest_ip, dest_port, user, auth_success, dns_query, host, raw) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        JdbcStatementBuilder<ParsedEvent> builder = (ps, e) -> {
            ps.setTimestamp(1, new Timestamp(e.eventTimeMillis));
            ps.setString(2, e.sourceType);
            ps.setString(3, e.sourceIp);
            ps.setString(4, e.destIp);
            if (e.destPort != null) {
                ps.setInt(5, e.destPort);
            } else {
                ps.setNull(5, java.sql.Types.INTEGER);
            }
            ps.setString(6, e.user);
            if (e.authSuccess != null) {
                ps.setBoolean(7, e.authSuccess);
            } else {
                ps.setNull(7, java.sql.Types.BOOLEAN);
            }
            ps.setString(8, e.dnsQuery);
            ps.setString(9, e.host);
            ps.setString(10, e.raw);
        };

        return build(sql, builder, jdbcUrl, user, password);
    }

    public static SinkFunction<Alert> alertsSink(String jdbcUrl, String user, String password) {
        String sql = "INSERT INTO siem.alerts " +
                "(detected_at, window_start, window_end, alert_type, source_type, source_ip, dest_ip, score, details) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

        JdbcStatementBuilder<Alert> builder = (ps, a) -> {
            ps.setTimestamp(1, new Timestamp(a.detectedAtMillis));
            ps.setTimestamp(2, new Timestamp(a.windowStartMillis));
            ps.setTimestamp(3, new Timestamp(a.windowEndMillis));
            ps.setString(4, a.alertType);
            ps.setString(5, a.sourceType);
            ps.setString(6, a.sourceIp);
            ps.setString(7, a.destIp);
            ps.setDouble(8, a.score);
            ps.setString(9, a.details);
        };

        return build(sql, builder, jdbcUrl, user, password);
    }

    private static <T> SinkFunction<T> build(String sql, JdbcStatementBuilder<T> builder,
                                              String jdbcUrl, String user, String password) {
        return JdbcSink.sink(
                sql,
                builder,
                JdbcExecutionOptions.builder()
                        .withBatchSize(1000)
                        .withBatchIntervalMs(2000) // flush at least every 2s even under low traffic, so the analyst dashboard isn't stale
                        .withMaxRetries(3)
                        .build(),
                new JdbcConnectionOptions.JdbcConnectionOptionsBuilder()
                        .withUrl(jdbcUrl)
                        .withDriverName("com.clickhouse.jdbc.ClickHouseDriver")
                        .withUsername(user)
                        .withPassword(password)
                        .build()
        );
    }
}
