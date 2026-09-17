package com.siem.functions;

import com.siem.model.Alert;
import com.siem.model.ParsedEvent;
import org.apache.flink.api.common.state.ValueState;
import org.apache.flink.api.common.state.ValueStateDescriptor;
import org.apache.flink.api.common.typeinfo.TypeInformation;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.util.Collector;

import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Detects C2-style beaconing: a source repeatedly connecting outbound at a
 * suspiciously *regular* interval. The signal is not the interval's length
 * (that varies by malware family and jitter config) but its LOW VARIANCE —
 * human/application traffic is bursty and irregular; a process on a timer
 * is not.
 *
 * Keyed by "sourceIp|destIp" (see SiemStreamJob) so we isolate a single
 * candidate C2 channel rather than blending all of a host's outbound
 * traffic together, which would wash out the regularity signal.
 *
 * State: a bounded sliding window of the last `maxSamples` event
 * timestamps for this key, kept in a single ValueState<TimestampBuffer>
 * (a ListState would also work, but a single ValueState round-trips one
 * object per element instead of N, which matters once this runs over real
 * traffic volume). We maintain one explicit event-time timer per key to
 * expire idle state — without it, a source that beacons for a day and then
 * goes quiet leaks its buffer forever.
 */
public class BeaconingDetector extends KeyedProcessFunction<String, ParsedEvent, Alert> {

    private final int maxSamples;
    private final int minSamples;
    private final double maxCoefficientOfVariation;
    private final long minIntervalMillis;
    private final long maxIntervalMillis;
    private final long idleExpiryMillis;

    private transient ValueState<TimestampBuffer> bufferState;
    private transient ValueState<Long> lastAlertMillis;
    private transient ValueState<Long> pendingExpiryTimer;

    public BeaconingDetector(int maxSamples, int minSamples, double maxCoefficientOfVariation,
                              long minIntervalMillis, long maxIntervalMillis, long idleExpiryMillis) {
        this.maxSamples = maxSamples;
        this.minSamples = minSamples;
        this.maxCoefficientOfVariation = maxCoefficientOfVariation;
        this.minIntervalMillis = minIntervalMillis;
        this.maxIntervalMillis = maxIntervalMillis;
        this.idleExpiryMillis = idleExpiryMillis;
    }

    @Override
    public void open(Configuration parameters) {
        bufferState = getRuntimeContext().getState(
                new ValueStateDescriptor<>("beacon-timestamp-buffer", TypeInformation.of(TimestampBuffer.class)));
        lastAlertMillis = getRuntimeContext().getState(
                new ValueStateDescriptor<>("beacon-last-alert", Long.class));
        pendingExpiryTimer = getRuntimeContext().getState(
                new ValueStateDescriptor<>("beacon-expiry-timer", Long.class));
    }

    @Override
    public void processElement(ParsedEvent event, Context ctx, Collector<Alert> out) throws Exception {
        if (!"firewall".equals(event.sourceType)) {
            return; // defensive; the job should only route firewall ALLOW events into this operator
        }

        TimestampBuffer buffer = bufferState.value();
        if (buffer == null) {
            buffer = new TimestampBuffer();
        }
        buffer.add(event.eventTimeMillis, maxSamples);
        bufferState.update(buffer);

        // Reset the idle-expiry timer to slide forward with each new event.
        Long existingTimer = pendingExpiryTimer.value();
        if (existingTimer != null) {
            ctx.timerService().deleteEventTimeTimer(existingTimer);
        }
        long newTimer = event.eventTimeMillis + idleExpiryMillis;
        ctx.timerService().registerEventTimeTimer(newTimer);
        pendingExpiryTimer.update(newTimer);

        if (buffer.size() < minSamples) {
            return;
        }

        double[] intervals = buffer.interArrivalIntervals();
        double mean = mean(intervals);
        double stddev = stddev(intervals, mean);
        double cv = mean > 0 ? stddev / mean : Double.MAX_VALUE;

        boolean regularInterval = cv <= maxCoefficientOfVariation;
        boolean plausibleBeaconRate = mean >= minIntervalMillis && mean <= maxIntervalMillis;

        if (regularInterval && plausibleBeaconRate) {
            Long lastAlert = lastAlertMillis.value();
            long cooldown = (long) (mean * 3); // don't re-alert on every single tick once a beacon is confirmed
            if (lastAlert == null || event.eventTimeMillis - lastAlert >= cooldown) {
                String sourceIp = ctx.getCurrentKey().split("\\|")[0];
                out.collect(new Alert(
                        "beaconing",
                        System.currentTimeMillis(),
                        event.eventTimeMillis - (long) (mean * buffer.size()),
                        event.eventTimeMillis,
                        sourceIp,
                        event.destIp,
                        Math.max(0.0, 1.0 - cv),
                        String.format("%d outbound connections to %s at ~%.1fs intervals (coefficient of variation=%.3f, threshold=%.3f)",
                                buffer.size(), event.destIp, mean / 1000.0, cv, maxCoefficientOfVariation),
                        "firewall"
                ));
                lastAlertMillis.update(event.eventTimeMillis);
            }
        }
    }

    @Override
    public void onTimer(long timestamp, OnTimerContext ctx, Collector<Alert> out) throws Exception {
        // No new event arrived within idleExpiryMillis of the last one for
        // this key: this candidate channel has gone quiet, so drop its
        // state rather than holding it forever. If traffic resumes later,
        // processElement simply starts a fresh buffer.
        bufferState.clear();
        lastAlertMillis.clear();
        pendingExpiryTimer.clear();
    }

    private static double mean(double[] xs) {
        double sum = 0;
        for (double x : xs) sum += x;
        return xs.length == 0 ? 0 : sum / xs.length;
    }

    private static double stddev(double[] xs, double mean) {
        if (xs.length == 0) return 0;
        double sumSq = 0;
        for (double x : xs) sumSq += (x - mean) * (x - mean);
        return Math.sqrt(sumSq / xs.length);
    }

    /** Bounded FIFO buffer of event timestamps, oldest evicted first. */
    public static class TimestampBuffer implements Serializable {
        private final Deque<Long> timestamps = new ArrayDeque<>();

        public void add(long ts, int maxSamples) {
            timestamps.addLast(ts);
            while (timestamps.size() > maxSamples) {
                timestamps.removeFirst();
            }
        }

        public int size() {
            return timestamps.size();
        }

        /** Consecutive differences between sorted timestamps, in milliseconds. */
        public double[] interArrivalIntervals() {
            Long[] sorted = timestamps.toArray(new Long[0]);
            java.util.Arrays.sort(sorted);
            double[] intervals = new double[Math.max(0, sorted.length - 1)];
            for (int i = 1; i < sorted.length; i++) {
                intervals[i - 1] = sorted[i] - sorted[i - 1];
            }
            return intervals;
        }
    }
}
