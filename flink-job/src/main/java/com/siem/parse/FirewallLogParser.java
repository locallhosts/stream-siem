package com.siem.parse;

import com.siem.model.ParsedEvent;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses lines like:
 *   2026-09-17T10:53:54Z ALLOW TCP src=10.0.1.12 dst=203.0.113.5 dport=443
 */
public class FirewallLogParser implements EventParser {

    private static final Pattern PATTERN = Pattern.compile(
            "^(?<ts>\\S+)\\s+(?<action>ALLOW|DENY)\\s+(?<proto>\\S+)\\s+src=(?<src>[0-9a-fA-F.:]+)\\s+dst=(?<dst>[0-9a-fA-F.:]+)\\s+dport=(?<port>\\d+)"
    );

    @Override
    public ParsedEvent parse(String host, String raw) throws ParseException {
        Matcher m = PATTERN.matcher(raw);
        if (!m.find()) {
            throw new ParseException("firewall line did not match expected format: " + raw);
        }
        long eventTimeMillis;
        try {
            eventTimeMillis = Instant.parse(m.group("ts")).toEpochMilli();
        } catch (DateTimeParseException e) {
            throw new ParseException("failed to parse firewall timestamp: " + m.group("ts"), e);
        }
        ParsedEvent event = new ParsedEvent("firewall", eventTimeMillis, m.group("src"), raw, host);
        event.destIp = m.group("dst");
        event.destPort = Integer.parseInt(m.group("port"));
        event.action = m.group("action");
        return event;
    }
}
