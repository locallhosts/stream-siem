package com.siem.functions;

import java.util.HashMap;
import java.util.Map;

public final class EntropyUtil {

    private EntropyUtil() {}

    /**
     * Shannon entropy in bits/char of a string. High-entropy subdomain
     * labels (close to log2(alphabet size), e.g. ~4 bits/char for
     * hex-encoded data) are the classic DNS-tunneling signature: legitimate
     * hostnames cluster much lower because they're made of pronounceable
     * words, not encoded payloads.
     */
    public static double shannonEntropy(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }
        Map<Character, Integer> counts = new HashMap<>();
        for (char c : s.toCharArray()) {
            counts.merge(c, 1, Integer::sum);
        }
        double entropy = 0.0;
        int n = s.length();
        for (int count : counts.values()) {
            double p = (double) count / n;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    /**
     * Average entropy across a query's dot-separated labels, excluding the
     * final two labels (the registrable domain, e.g. "badhost.net"), since
     * that part is attacker-chosen infrastructure, not the exfiltrated
     * payload, and including it would dilute the signal on short queries.
     */
    public static double averageSubdomainEntropy(String query) {
        if (query == null) {
            return 0.0;
        }
        String[] labels = query.split("\\.");
        if (labels.length <= 2) {
            return shannonEntropy(labels.length > 0 ? labels[0] : "");
        }
        double sum = 0.0;
        int considered = labels.length - 2;
        for (int i = 0; i < considered; i++) {
            sum += shannonEntropy(labels[i]);
        }
        return sum / considered;
    }
}
