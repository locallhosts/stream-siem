package com.siem.parse;

import com.siem.model.ParsedEvent;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses lines like:
 *   2026-09-17T10:53:54Z queries: client 10.0.7.50#32621: query: example.com IN A + (10.0.0.1)
 */
public class DnsLogParser implements EventParser {

    private static final Pattern PATTERN = Pattern.compile(
            "^(?<ts>\\S+)\\s+queries:\\s+client\\s+(?<ip>[0-9a-fA-F.:]+)#\\d+:\\s+query:\\s+(?<query>\\S+)\\s+IN"
    );

    @Override
    public ParsedEvent parse(String host, String raw) throws ParseException {
        Matcher m = PATTERN.matcher(raw);
        if (!m.find()) {
            throw new ParseException("dns line did not match expected format: " + raw);
        }
        long eventTimeMillis;
        try {
            eventTimeMillis = Instant.parse(m.group("ts")).toEpochMilli();
        } catch (DateTimeParseException e) {
            throw new ParseException("failed to parse dns timestamp: " + m.group("ts"), e);
        }
        ParsedEvent event = new ParsedEvent("dns", eventTimeMillis, m.group("ip"), raw, host);
        event.dnsQuery = m.group("query");
        return event;
    }
}
