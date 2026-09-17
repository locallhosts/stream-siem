package com.siem.functions;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EntropyUtilTest {

    @Test
    void singleCharacterStringHasZeroEntropy() {
        assertEquals(0.0, EntropyUtil.shannonEntropy("aaaaaa"), 1e-9);
    }

    @Test
    void hexEncodedLabelHasHigherEntropyThanAWord() {
        double wordEntropy = EntropyUtil.shannonEntropy("mail");
        double hexEntropy = EntropyUtil.shannonEntropy("1a0b6fae90f7338eb6ab51ce6f5da253");
        assertTrue(hexEntropy > wordEntropy,
                "hex-encoded label (" + hexEntropy + ") should have higher entropy than an English word (" + wordEntropy + ")");
    }

    @Test
    void averageSubdomainEntropyExcludesRegistrableDomain() {
        // "mail" and "example.com" -> only "mail" is scored
        double withPlainLabel = EntropyUtil.averageSubdomainEntropy("mail.example.com");
        assertEquals(EntropyUtil.shannonEntropy("mail"), withPlainLabel, 1e-9);
    }

    @Test
    void tunnelingQueryScoresHigherThanBenignQuery() {
        double benign = EntropyUtil.averageSubdomainEntropy("mail.example.com");
        double tunneling = EntropyUtil.averageSubdomainEntropy(
                "1a0b6fae90f7338eb6ab51ce6f5da253.0fbc279891e69158d713e9a9e45ff0f6.exfil.badhost.net");
        assertTrue(tunneling > benign);
    }
}
