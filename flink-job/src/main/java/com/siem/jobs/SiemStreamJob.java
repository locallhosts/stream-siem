package com.siem.jobs;

import com.siem.functions.BeaconingDetector;
import com.siem.functions.DnsTunnelingDetector;
import com.siem.functions.FailedLoginRateDetector;
import com.siem.model.Alert;
import com.siem.model.DnsTunnelingModelParams;
import com.siem.model.ParsedEvent;
import com.siem.parse.EventParsingFunction;
import com.siem.sink.AlertKafkaSerializer;
import com.siem.sink.ClickHouseSinks;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.serialization.SimpleStringSchema;
import org.apache.flink.api.java.utils.ParameterTool;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.kafka.clients.consumer.OffsetResetStrategy;
import org.apache.flink.streaming.api.CheckpointingMode;
import org.apache.flink.streaming.api.TimeCharacteristic;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.datastream.SingleOutputStreamOperator;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.windowing.assigners.TumblingEventTimeWindows;
import org.apache.flink.streaming.api.windowing.time.Time;
import org.apache.flink.util.OutputTag;

import java.time.Duration;

public class SiemStreamJob {

    // Side output for events that arrive after the watermark + allowed
    // lateness has already passed for their window. We do NOT silently drop
    // these: routing them here makes late-data volume observable (alert on
    // it if it's ever nonzero and large — that usually means a forwarder
    // clock is skewed or a source is replaying old files).
    private static final OutputTag<ParsedEvent> LATE_AUTH_TAG =
            new OutputTag<ParsedEvent>("late-auth-events") {};

    public static void main(String[] args) throws Exception {
        ParameterTool params = ParameterTool.fromArgs(args);

        String kafkaBrokers = params.get("kafka-brokers", "kafka:29092");
        String rawTopic = params.get("raw-topic", "siem.raw.events");
        String alertTopic = params.get("alert-topic", "siem.alerts");
        String deadLetterTopic = params.get("dead-letter-topic", "siem.dead-letters");
        String consumerGroup = params.get("consumer-group", "siem-flink-job");

        String clickhouseUrl = params.get(
        "clickhouse-url",
        System.getenv().getOrDefault(
                "CLICKHOUSE_URL",
                "jdbc:ch://clickhouse:8123/siem"
        )
        );

        String clickhouseUser = params.get(
                "clickhouse-user",
                System.getenv().getOrDefault(
                        "CLICKHOUSE_USER",
                        "default"
                )
        );

        String clickhousePassword = params.get(
                "clickhouse-password",
                System.getenv().getOrDefault(
                        "CLICKHOUSE_PASSWORD",
                        ""
                )
        );

        // Failed-login-rate thresholds
        int failedLoginThreshold = params.getInt("failed-login-threshold", 10);

        // Beaconing thresholds
        int beaconMaxSamples = params.getInt("beacon-max-samples", 20);
        int beaconMinSamples = params.getInt("beacon-min-samples", 5);
        double beaconMaxCv = params.getDouble("beacon-max-cv", 0.15);
        long beaconMinIntervalMillis = params.getLong("beacon-min-interval-ms", 5_000L);
        long beaconMaxIntervalMillis = params.getLong("beacon-max-interval-ms", 3_600_000L);
        long beaconIdleExpiryMillis = Time.minutes(15).toMilliseconds();

        // DNS tunneling model: load offline-trained baseline if a path was
        // given, else fall back to sane defaults (see DnsTunnelingModelParams).
        DnsTunnelingModelParams dnsModel;
        String modelPath = params.get("dns-model-path", null);
        if (modelPath != null) {
            dnsModel = DnsTunnelingModelParams.loadFromJson(modelPath);
        } else {
            dnsModel = DnsTunnelingModelParams.defaults();
        }

        StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();
        env.setStreamTimeCharacteristic(TimeCharacteristic.EventTime);
        // Exactly-once end-to-end requires checkpointing on (source offsets +
        // any state we hold are only committed together on checkpoint
        // barriers) plus idempotent or transactional sinks. Our ClickHouse
        // JDBC sink is at-least-once (a replayed batch after a failure can
        // duplicate rows) — see the README's "exactly-once" section for what
        // it would take to close that last gap (a dedup key + ReplacingMergeTree,
        // or a two-phase-commit sink).
        env.enableCheckpointing(30_000, CheckpointingMode.EXACTLY_ONCE);
        env.getCheckpointConfig().setMinPauseBetweenCheckpoints(10_000);
        env.getCheckpointConfig().setCheckpointTimeout(120_000);

        KafkaSource<String> kafkaSource = KafkaSource.<String>builder()
                .setBootstrapServers(kafkaBrokers)
                .setTopics(rawTopic)
                .setGroupId(consumerGroup)
                // Resume from the consumer group's committed offset on restart
                // (the normal case); if this group has never committed an
                // offset for a partition (first-ever run), fall back to
                // reading from the earliest available record rather than
                // throwing.
                .setStartingOffsets(OffsetsInitializer.committedOffsets(OffsetResetStrategy.EARLIEST))
                .setValueOnlyDeserializer(new SimpleStringSchema())
                .build();

        DataStream<String> rawStream = env.fromSource(
                kafkaSource, WatermarkStrategy.noWatermarks(), "kafka-raw-events");

        // Parsing must happen before watermarking: event time lives inside
        // the raw log line's own timestamp, which we can't see until after
        // EventParsingFunction extracts it into ParsedEvent.eventTimeMillis.
        SingleOutputStreamOperator<ParsedEvent> parsed = rawStream
                .process(new EventParsingFunction())
                .name("parse-events")
                .uid("parse-events");

        parsed.getSideOutput(EventParsingFunction.DEAD_LETTER_TAG)
                .sinkTo(stringKafkaSink(kafkaBrokers, deadLetterTopic))
                .name("dead-letter-sink");

        // Bounded-out-of-orderness watermarks: we assume no event is more
        // than 30s late relative to the max timestamp seen so far. Any event
        // that arrives *after* its window has already closed and fired
        // (window end + allowedLateness) is routed to a side output instead
        // of being silently dropped — see LATE_AUTH_TAG below and the
        // README for the full explanation of what "late" means here and why
        // 30s + 30s allowed lateness was chosen over, say, a larger bound.
        //
        // withIdleness(2 min): if a partition (e.g. the firewall source_type
        // partition) stops producing entirely, its watermark would otherwise
        // stall forever and hold back the whole job's watermark (since
        // Flink's combined watermark is the MIN across all inputs). Marking
        // a source idle after 2 minutes of silence lets the watermark keep
        // advancing from the remaining active partitions.
        DataStream<ParsedEvent> withWatermarks = parsed.assignTimestampsAndWatermarks(
                WatermarkStrategy.<ParsedEvent>forBoundedOutOfOrderness(Duration.ofSeconds(30))
                        .withTimestampAssigner((event, recordTimestamp) -> event.eventTimeMillis)
                        .withIdleness(Duration.ofMinutes(2))
        ).name("assign-watermarks");

        // All parsed events land in ClickHouse for ad-hoc analyst queries,
        // independent of whether any detector fires on them.
        withWatermarks.addSink(ClickHouseSinks.enrichedEventsSink(clickhouseUrl, clickhouseUser, clickhousePassword))
                .name("clickhouse-enriched-events-sink")
                .uid("clickhouse-enriched-events-sink");

        // --- Detector 1: failed-login rate (tumbling window) ---
        SingleOutputStreamOperator<Alert> failedLoginAlerts = withWatermarks
                .filter(e -> "auth".equals(e.sourceType))
                .keyBy(e -> e.sourceIp)
                .window(TumblingEventTimeWindows.of(Time.minutes(5)))
                .allowedLateness(Time.seconds(30))
                .sideOutputLateData(LATE_AUTH_TAG)
                .process(new FailedLoginRateDetector(failedLoginThreshold))
                .name("failed-login-rate-detector")
                .uid("failed-login-rate-detector");

        failedLoginAlerts.getSideOutput(LATE_AUTH_TAG)
                .map(e -> "late_auth_event: " + e.raw)
                .returns(String.class)
                .sinkTo(stringKafkaSink(kafkaBrokers, deadLetterTopic))
                .name("late-data-sink");

        // --- Detector 2: beaconing (stateful KeyedProcessFunction) ---
        DataStream<Alert> beaconAlerts = withWatermarks
                .filter(e -> "firewall".equals(e.sourceType) && "ALLOW".equalsIgnoreCase(e.action))
                .keyBy(e -> e.sourceIp + "|" + e.destIp)
                .process(new BeaconingDetector(
                        beaconMaxSamples, beaconMinSamples, beaconMaxCv,
                        beaconMinIntervalMillis, beaconMaxIntervalMillis, beaconIdleExpiryMillis))
                .name("beaconing-detector")
                .uid("beaconing-detector");

        // --- Detector 3: DNS tunneling (stateful KeyedProcessFunction + offline model) ---
        DataStream<Alert> dnsTunnelingAlerts = withWatermarks
                .filter(e -> "dns".equals(e.sourceType))
                .keyBy(e -> e.sourceIp)
                .process(new DnsTunnelingDetector(dnsModel))
                .name("dns-tunneling-detector")
                .uid("dns-tunneling-detector");

        DataStream<Alert> allAlerts = failedLoginAlerts.union(beaconAlerts, dnsTunnelingAlerts);

        allAlerts.addSink(ClickHouseSinks.alertsSink(clickhouseUrl, clickhouseUser, clickhousePassword))
                .name("clickhouse-alerts-sink")
                .uid("clickhouse-alerts-sink");

        allAlerts.sinkTo(alertKafkaSink(kafkaBrokers, alertTopic))
                .name("kafka-alert-sink")
                .uid("kafka-alert-sink");

        allAlerts.print("ALERT"); // stdout visibility for local dev / docker-compose logs

        env.execute("siem-stream-job");
    }

    private static KafkaSink<String> stringKafkaSink(String brokers, String topic) {
        return KafkaSink.<String>builder()
                .setBootstrapServers(brokers)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(topic)
                        .setValueSerializationSchema(new SimpleStringSchema())
                        .build())
                .build();
    }

    private static KafkaSink<Alert> alertKafkaSink(String brokers, String topic) {
        return KafkaSink.<Alert>builder()
                .setBootstrapServers(brokers)
                .setRecordSerializer(KafkaRecordSerializationSchema.builder()
                        .setTopic(topic)
                        .setValueSerializationSchema(new AlertKafkaSerializer())
                        .build())
                .build();
    }
}
