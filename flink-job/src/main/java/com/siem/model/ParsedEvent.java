package com.siem.model;

import java.io.Serializable;

/**
 * Normalized event shape all detectors operate on, regardless of which
 * source_type produced it. Fields are nullable/zero-valued when not
 * applicable to a given source type (e.g. `success` is meaningless for a
 * firewall event).
 *
 * eventTimeMillis is the timestamp *parsed out of the log line itself*
 * (e.g. sshd's "Sep 17 10:22:01"), not the time the forwarder observed it.
 * That distinction is what makes watermarking meaningful here: a batch of
 * auth.log lines replayed from disk, or delayed by a slow forwarder, carries
 * its true origin time, and Flink's watermarks are computed from that field
 * — see EventParsingFunction and SiemStreamJob for how out-of-order/late
 * events are handled.
 */
public class ParsedEvent implements Serializable {

    public String sourceType;      // "auth" | "dns" | "firewall"
    public long eventTimeMillis;   // parsed from the log line; drives watermarks
    public String sourceIp;        // the host that generated the traffic/action
    public String destIp;          // nullable
    public Integer destPort;       // nullable
    public String action;          // nullable, firewall only: "ALLOW" | "DENY"
    public String user;            // nullable, auth only
    public Boolean authSuccess;    // nullable, auth only
    public String dnsQuery;        // nullable, dns only
    public String host;            // forwarder node_id that observed this
    public String raw;             // original line, kept for alert context

    public ParsedEvent() {}

    public ParsedEvent(String sourceType, long eventTimeMillis, String sourceIp, String raw, String host) {
        this.sourceType = sourceType;
        this.eventTimeMillis = eventTimeMillis;
        this.sourceIp = sourceIp;
        this.raw = raw;
        this.host = host;
    }

    @Override
    public String toString() {
        return "ParsedEvent{" +
                "sourceType='" + sourceType + '\'' +
                ", eventTimeMillis=" + eventTimeMillis +
                ", sourceIp='" + sourceIp + '\'' +
                ", destIp='" + destIp + '\'' +
                ", destPort=" + destPort +
                ", user='" + user + '\'' +
                ", authSuccess=" + authSuccess +
                ", dnsQuery='" + dnsQuery + '\'' +
                '}';
    }
}
