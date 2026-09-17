package com.siem.functions;

import com.siem.model.Alert;
import com.siem.model.DnsTunnelingModelParams;
import com.siem.model.ParsedEvent;
import org.apache.flink.api.common.state.ValueState;
import org.apache.flink.api.common.state.ValueStateDescriptor;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.util.Collector;

import java.io.Serializable;

/**
 * Flags sources whose average DNS query-label entropy in a rolling window
 * is a statistical outlier against an offline-trained baseline — the
 * classic DNS-tunneling signature (see EntropyUtil for why entropy is the
 * right signal).
 *
 * Implementation note: unlike BeaconingDetector, this keeps only running
 * sums (count, sum of entropy, sum of entropy^2) rather than buffering
 * every query string. That's the standard streaming-statistics trick
 * (single-pass mean/variance) and it means this operator's state size is
 * O(1) per key regardless of query volume, which matters because DNS
 * volume per host is typically much higher than firewall-connection volume.
 */
public class DnsTunnelingDetector extends KeyedProcessFunction<String, ParsedEvent, Alert> {

    private final DnsTunnelingModelParams model;

    private transient ValueState<WindowAccumulator> accState;

    public DnsTunnelingDetector(DnsTunnelingModelParams model) {
        this.model = model;
    }

    @Override
    public void open(Configuration parameters) {
        accState = getRuntimeContext().getState(
                new ValueStateDescriptor<>("dns-window-accumulator", WindowAccumulator.class));
    }

    @Override
    public void processElement(ParsedEvent event, Context ctx, Collector<Alert> out) throws Exception {
        if (!"dns".equals(event.sourceType) || event.dnsQuery == null) {
            return;
        }

        WindowAccumulator acc = accState.value();
        if (acc == null) {
            acc = new WindowAccumulator();
            acc.windowStartMillis = event.eventTimeMillis;
            ctx.timerService().registerEventTimeTimer(event.eventTimeMillis + model.windowSizeMillis);
        }

        double entropy = EntropyUtil.averageSubdomainEntropy(event.dnsQuery);
        acc.count++;
        acc.sumEntropy += entropy;
        acc.sumEntropySquared += entropy * entropy;
        acc.lastQuery = event.dnsQuery;
        acc.lastEventTimeMillis = event.eventTimeMillis;
        accState.update(acc);
    }

    @Override
    public void onTimer(long timestamp, OnTimerContext ctx, Collector<Alert> out) throws Exception {
        WindowAccumulator acc = accState.value();
        accState.clear(); // tumbling: always start the next window fresh, whether or not we alerted

        if (acc == null || acc.count < model.minQueriesPerWindow) {
            return;
        }

        double meanEntropy = acc.sumEntropy / acc.count;
        double zScore = model.baselineStdEntropy > 0
                ? (meanEntropy - model.baselineMeanEntropy) / model.baselineStdEntropy
                : 0;

        if (zScore >= model.zScoreThreshold) {
            String sourceIp = ctx.getCurrentKey();
            double score = Math.min(1.0, zScore / (model.zScoreThreshold * 2));
            out.collect(new Alert(
                    "dns_tunneling",
                    System.currentTimeMillis(),
                    acc.windowStartMillis,
                    timestamp,
                    sourceIp,
                    null,
                    score,
                    String.format("%d DNS queries from %s, mean subdomain entropy %.2f bits/char " +
                                    "(baseline %.2f +/- %.2f, z-score %.2f, threshold %.2f). Example query: %s",
                            acc.count, sourceIp, meanEntropy, model.baselineMeanEntropy, model.baselineStdEntropy,
                            zScore, model.zScoreThreshold, acc.lastQuery),
                    "dns"
            ));
        }
    }

    /** Running (count, sum, sum-of-squares) accumulator for one tumbling window at one key. */
    public static class WindowAccumulator implements Serializable {
        public long count;
        public double sumEntropy;
        public double sumEntropySquared;
        public long windowStartMillis;
        public long lastEventTimeMillis;
        public String lastQuery;
    }
}
