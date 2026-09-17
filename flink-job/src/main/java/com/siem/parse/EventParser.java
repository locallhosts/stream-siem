package com.siem.parse;

import com.siem.model.ParsedEvent;

/**
 * A ParseException means "this line doesn't match the format we expect for
 * this source_type" — the caller (EventParsingFunction) routes these to a
 * side output rather than dropping them silently, so malformed/unexpected
 * log formats are visible instead of quietly vanishing.
 */
public interface EventParser {
    ParsedEvent parse(String host, String raw) throws ParseException;

    class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
        public ParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
