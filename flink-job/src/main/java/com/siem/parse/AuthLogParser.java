package com.siem.parse;

import com.siem.model.ParsedEvent;

import java.time.LocalDateTime;
import java.time.Year;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses lines like:
 *   Sep 17 10:22:01 sshd[1234]: Accepted publickey for alice from 10.0.1.12 port 54321 ssh2
 *   Sep 17 10:22:01 sshd[1234]: Failed password for bob from 10.0.1.45 port 54322 ssh2
 *
 * Traditional syslog (RFC 3164) timestamps carry no year, so we assume the
 * current year at parse time. This is a real, well-known gotcha in log
 * pipelines (it breaks silently on Dec 31 -> Jan 1 replays of old logs) —
 * flagged here rather than hidden, and worth calling out in interviews.
 */
public class AuthLogParser implements EventParser {

    private static final Pattern PATTERN = Pattern.compile(
            "^(?<ts>\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+sshd\\[\\d+\\]:\\s+" +
                    "(?<result>Accepted|Failed)\\s+\\S+\\s+for\\s+(?<user>\\S+)\\s+from\\s+(?<ip>[0-9a-fA-F.:]+)\\s+port\\s+(?<port>\\d+)"
    );

    // Locale pinned to English explicitly: syslog month abbreviations ("Sep",
    // "Oct", ...) are always English regardless of the JVM's default locale,
    // and DateTimeFormatter.ofPattern("MMM"...) without a Locale silently
    // uses whatever locale the taskmanager JVM happens to be running under —
    // a real bug that only shows up when you deploy to a host configured
    // with a non-English locale, long after this parses fine in local dev.
    private static final DateTimeFormatter TS_FORMAT =
            DateTimeFormatter.ofPattern("yyyy MMM d HH:mm:ss", java.util.Locale.ENGLISH);

    @Override
    public ParsedEvent parse(String host, String raw) throws ParseException {
        Matcher m = PATTERN.matcher(raw);
        if (!m.find()) {
            throw new ParseException("auth line did not match expected sshd format: " + raw);
        }

        long eventTimeMillis;
        try {
            String normalizedTs = m.group("ts").replaceAll("\\s+", " ").trim();
            LocalDateTime withoutYear = LocalDateTime.parse(
                    Year.now(ZoneOffset.UTC).getValue() + " " + normalizedTs,
                    TS_FORMAT
            );
            eventTimeMillis = withoutYear.toInstant(ZoneOffset.UTC).toEpochMilli();
        } catch (Exception e) {
            throw new ParseException("failed to parse auth timestamp: " + m.group("ts"), e);
        }

        ParsedEvent event = new ParsedEvent("auth", eventTimeMillis, m.group("ip"), raw, host);
        event.user = m.group("user");
        event.authSuccess = "Accepted".equals(m.group("result"));
        return event;
    }
}
