package com.siem.functions;

import com.siem.model.Alert;
import com.siem.model.ParsedEvent;
import org.apache.flink.streaming.api.windowing.windows.TimeWindow;
import org.apache.flink.streaming.api.functions.windowing.ProcessWindowFunction;
import org.apache.flink.util.Collector;

/**
 * Runs over a 5-minute TUMBLING event-time window, keyed by sourceIp
 * (applied only to source_type=="auth" events upstream — see
 * SiemStreamJob). Emits an Alert if the count of failed logins for that IP
 * in the window meets or exceeds threshold.
 *
 * Why tumbling and not sliding here: brute-force detection doesn't need
 * overlapping windows re-evaluating the same events repeatedly (that's
 * useful for smoother beaconing detection, not for a simple rate count);
 * tumbling keeps state and computation an order of magnitude cheaper for
 * this specific detector.
 */
public class FailedLoginRateDetector
        extends ProcessWindowFunction<ParsedEvent, Alert, String, TimeWindow> {

    private final int threshold;

    public FailedLoginRateDetector(int threshold) {
        this.threshold = threshold;
    }

    @Override
    public void process(String sourceIp, Context context, Iterable<ParsedEvent> events, Collector<Alert> out) {
        int failedCount = 0;
        int totalCount = 0;
        for (ParsedEvent e : events) {
            totalCount++;
            if (Boolean.FALSE.equals(e.authSuccess)) {
                failedCount++;
            }
        }
        if (failedCount >= threshold) {
            TimeWindow window = context.window();
            out.collect(new Alert(
                    "failed_login_rate",
                    System.currentTimeMillis(),
                    window.getStart(),
                    window.getEnd(),
                    sourceIp,
                    null,
                    Math.min(1.0, failedCount / (double) (threshold * 3)),
                    String.format("%d failed logins (of %d total auth events) from %s in a 5-minute window (threshold=%d)",
                            failedCount, totalCount, sourceIp, threshold),
                    "auth"
            ));
        }
    }
}
