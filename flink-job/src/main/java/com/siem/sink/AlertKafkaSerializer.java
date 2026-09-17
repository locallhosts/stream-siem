package com.siem.sink;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.model.Alert;
import org.apache.flink.api.common.serialization.SerializationSchema;

public class AlertKafkaSerializer implements SerializationSchema<Alert> {

    private transient ObjectMapper mapper;

    @Override
    public void open(InitializationContext context) {
        mapper = new ObjectMapper();
    }

    @Override
    public byte[] serialize(Alert alert) {
        try {
            if (mapper == null) {
                mapper = new ObjectMapper(); // defensive: open() should have run, but don't NPE if a test constructs this directly
            }
            return mapper.writeValueAsBytes(alert);
        } catch (Exception e) {
            throw new RuntimeException("failed to serialize alert to JSON", e);
        }
    }
}
