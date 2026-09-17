package com.siem.parse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.siem.model.ParsedEvent;
import com.siem.model.RawEnvelope;
import org.apache.flink.streaming.api.functions.ProcessFunction;
import org.apache.flink.util.Collector;
import org.apache.flink.util.OutputTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Input: raw JSON strings as produced by the Go forwarder onto Kafka topic
 * siem.raw.events (see RawEnvelope).
 * Output: ParsedEvent, with eventTimeMillis populated from the log line's
 * own timestamp — this is the field the watermark strategy in
 * SiemStreamJob uses, NOT Flink processing time and NOT the forwarder's
 * received_at.
 *
 * Anything that fails JSON decoding, has an unknown source_type, or fails
 * its source-type-specific regex is routed to DEAD_LETTER_TAG instead of
 * being silently dropped, so format drift in upstream log sources is
 * observable rather than invisible.
 */
public class EventParsingFunction extends ProcessFunction<String, ParsedEvent> {

    public static final OutputTag<String> DEAD_LETTER_TAG =
            new OutputTag<String>("dead-letters") {};

    private static final Logger LOG = LoggerFactory.getLogger(EventParsingFunction.class);

    private transient ObjectMapper mapper;
    private transient Map<String, EventParser> parsers;

    @Override
    public void open(org.apache.flink.configuration.Configuration parameters) {
        mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        parsers = new ConcurrentHashMap<>();
        parsers.put("auth", new AuthLogParser());
        parsers.put("dns", new DnsLogParser());
        parsers.put("firewall", new FirewallLogParser());
    }

    @Override
    public void processElement(String rawJson, Context ctx, Collector<ParsedEvent> out) {
        RawEnvelope envelope;
        try {
            envelope = mapper.readValue(rawJson, RawEnvelope.class);
        } catch (Exception e) {
            LOG.debug("failed to decode envelope JSON: {}", e.getMessage());
            ctx.output(DEAD_LETTER_TAG, "json_decode_error: " + rawJson);
            return;
        }

        EventParser parser = parsers.get(envelope.sourceType);
        if (parser == null) {
            ctx.output(DEAD_LETTER_TAG, "unknown_source_type(" + envelope.sourceType + "): " + rawJson);
            return;
        }

        try {
            ParsedEvent parsed = parser.parse(envelope.host, envelope.raw);
            out.collect(parsed);
        } catch (EventParser.ParseException e) {
            LOG.debug("failed to parse {} line: {}", envelope.sourceType, e.getMessage());
            ctx.output(DEAD_LETTER_TAG, "parse_error(" + envelope.sourceType + "): " + rawJson);
        }
    }
}
