package com.siem.model;

import java.io.Serializable;

/**
 * Uniform alert schema across all detectors. `details` carries a short
 * human-readable explanation and `score` a 0-1 confidence, so downstream
 * consumers (dashboard, SOAR) don't need per-detector-type parsing logic.
 */
public class Alert implements Serializable {

    public String alertType;    // "failed_login_rate" | "beaconing" | "dns_tunneling"
    public long detectedAtMillis;
    public long windowStartMillis;
    public long windowEndMillis;
    public String sourceIp;
    public String destIp;       // nullable
    public double score;        // 0.0-1.0, detector-specific confidence
    public String details;
    public String sourceType;   // originating source_type ("auth" | "firewall" | "dns")

    public Alert() {}

    public Alert(String alertType, long detectedAtMillis, long windowStartMillis, long windowEndMillis,
                 String sourceIp, String destIp, double score, String details, String sourceType) {
        this.alertType = alertType;
        this.detectedAtMillis = detectedAtMillis;
        this.windowStartMillis = windowStartMillis;
        this.windowEndMillis = windowEndMillis;
        this.sourceIp = sourceIp;
        this.destIp = destIp;
        this.score = score;
        this.details = details;
        this.sourceType = sourceType;
    }

    @Override
    public String toString() {
        return "Alert{" +
                "alertType='" + alertType + '\'' +
                ", sourceIp='" + sourceIp + '\'' +
                ", destIp='" + destIp + '\'' +
                ", score=" + score +
                ", details='" + details + '\'' +
                '}';
    }
}
