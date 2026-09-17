package com.siem.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.time.Instant;

/**
 * Mirrors the JSON shape written by the Go forwarder (see
 * go-forwarder/internal/source/source.go: Event). Field names use the
 * forwarder's snake_case JSON tags.
 */
public class RawEnvelope implements Serializable {

    @JsonProperty("source_type")
    public String sourceType;

    @JsonProperty("host")
    public String host;

    @JsonProperty("received_at")
    public Instant receivedAt;

    @JsonProperty("raw")
    public String raw;

    public RawEnvelope() {
        // required by Jackson
    }
}
