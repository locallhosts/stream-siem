package com.siem.functions;

import com.siem.model.Alert;
import com.siem.model.ParsedEvent;
import org.apache.flink.api.common.typeinfo.TypeInformation;
import org.apache.flink.streaming.api.operators.KeyedProcessOperator;
import org.apache.flink.streaming.util.KeyedOneInputStreamOperatorTestHarness;
import org.apache.flink.streaming.runtime.streamrecord.StreamRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Uses Flink's KeyedOneInputStreamOperatorTestHarness to drive event-time
 * and watermarks explicitly, which is the standard way to unit test a
 * KeyedProcessFunction that relies on timers and event time — you cannot
 * meaningfully test this kind of operator with plain JUnit calls, because
 * its behavior IS its reaction to a sequence of watermark-ordered events.
 */
class BeaconingDetectorTest {

    private KeyedOneInputStreamOperatorTestHarness<String, ParsedEvent, Alert> harness;

    @BeforeEach
    void setUp() throws Exception {
        BeaconingDetector detector = new BeaconingDetector(
                /* maxSamples */ 10,
                /* minSamples */ 5,
                /* maxCoefficientOfVariation */ 0.15,
                /* minIntervalMillis */ 1_000,
                /* maxIntervalMillis */ 3_600_000,
                /* idleExpiryMillis */ TimeUnit.MINUTES.toMillis(15)
        );
        harness = new KeyedOneInputStreamOperatorTestHarness<>(
                new KeyedProcessOperator<>(detector),
                (ParsedEvent e) -> e.sourceIp + "|" + e.destIp,
                TypeInformation.of(String.class)
        );
        harness.open();
    }

    @AfterEach
    void tearDown() throws Exception {
        harness.close();
    }

    private ParsedEvent firewallEvent(long timeMillis, String srcIp, String dstIp) {
        ParsedEvent e = new ParsedEvent("firewall", timeMillis, srcIp, "ALLOW TCP src=" + srcIp + " dst=" + dstIp, "test-host");
        e.destIp = dstIp;
        e.action = "ALLOW";
        return e;
    }

    @Test
    void firesOnRegularThirtySecondIntervalTraffic() throws Exception {
        long base = 1_700_000_000_000L;
        long intervalMillis = 30_000;

        // Six connections at an almost-exactly-30s interval (small jitter,
        // well within the 0.15 coefficient-of-variation threshold).
        long[] jitterMillis = {0, 400, -300, 200, -100, 500};
        for (int i = 0; i < jitterMillis.length; i++) {
            long ts = base + i * intervalMillis + jitterMillis[i];
            harness.processElement(new StreamRecord<>(firewallEvent(ts, "10.0.6.200", "198.51.100.77"), ts));
            harness.processWatermark(ts - 1); // advance watermark just behind the event, as SiemStreamJob's bounded-out-of-orderness strategy would
        }

        List<Alert> alerts = harness.extractOutputValues();
        assertFalse(alerts.isEmpty(), "expected at least one beaconing alert on regular-interval traffic");
        Alert alert = alerts.get(0);
        assertEquals("beaconing", alert.alertType);
        assertEquals("10.0.6.200", alert.sourceIp);
        assertEquals("198.51.100.77", alert.destIp);
    }

    @Test
    void staysSilentOnIrregularIntervalTraffic() throws Exception {
        long base = 1_700_000_000_000L;
        // Wildly irregular intervals: 2s, 47s, 5s, 90s, 12s — high
        // coefficient of variation, should not be flagged as beaconing.
        long[] offsetsMillis = {0, 2_000, 49_000, 54_000, 144_000, 156_000};

        for (long offset : offsetsMillis) {
            long ts = base + offset;
            harness.processElement(new StreamRecord<>(firewallEvent(ts, "10.0.1.12", "203.0.113.9"), ts));
            harness.processWatermark(ts - 1);
        }

        List<Alert> alerts = harness.extractOutputValues();
        assertTrue(alerts.isEmpty(), "irregular-interval traffic should not trigger a beaconing alert, but got: " + alerts);
    }
}
