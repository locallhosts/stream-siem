package com.siem.model;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Mirrors the JSON written by ml-model/train_dns_entropy_model.py. This is
 * the "train offline, score online" boundary: the Python script computes
 * these four numbers once, in batch, from a corpus of (assumed benign)
 * historical DNS logs; the Flink job just loads them at startup and scores
 * live traffic against them with simple arithmetic — no ML runtime, no
 * model server, no per-event Python call. That split is what actually
 * makes "ML-based" stream detectors operable at Kafka-scale throughput.
 */
public class DnsTunnelingModelParams implements Serializable {

    public double baselineMeanEntropy;
    public double baselineStdEntropy;
    public double zScoreThreshold;
    public int minQueriesPerWindow;
    public long windowSizeMillis;

    public DnsTunnelingModelParams() {}

    public DnsTunnelingModelParams(double baselineMeanEntropy, double baselineStdEntropy,
                                    double zScoreThreshold, int minQueriesPerWindow, long windowSizeMillis) {
        this.baselineMeanEntropy = baselineMeanEntropy;
        this.baselineStdEntropy = baselineStdEntropy;
        this.zScoreThreshold = zScoreThreshold;
        this.minQueriesPerWindow = minQueriesPerWindow;
        this.windowSizeMillis = windowSizeMillis;
    }

    /** Sensible fallback if no trained model file is supplied (e.g. first-ever run, before ml-model has produced one).
     *  Calibrated against this project's synthetic benign corpus (mean~2.01, std~0.48 bits/char); the tunneling
     *  Zscore-Threshold is empirically well below the trained beacon (~2.45) -> see ml-model/README for how to retrain
     *  on your own traffic instead of relying on this fallback. */
    public static DnsTunnelingModelParams defaults() {
        return new DnsTunnelingModelParams(2.0, 0.48, 2.0, 8, 60_000L);
    }

    public static DnsTunnelingModelParams loadFromJson(String path) throws IOException {
        byte[] bytes = Files.readAllBytes(Path.of(path));
        return new ObjectMapper().readValue(bytes, DnsTunnelingModelParams.class);
    }
}
