#!/usr/bin/env python3
"""Trains the DNS-tunneling entropy baseline offline, on batch log data, and
writes the small JSON file the Flink job (DnsTunnelingModelParams) loads at
startup to score live traffic. This is the "train offline, score online"
split described in the project brief: everything statistically expensive
happens once, here, in batch; the Flink job just does arithmetic against
four numbers per event.

Usage:
    python3 train_dns_entropy_model.py --input /path/to/dns.log --output model_params.json

The entropy calculation here MUST match EntropyUtil.averageSubdomainEntropy
in the Flink job exactly, or the trained baseline won't mean what the online
scorer thinks it means -- see entropy() below and its Java counterpart.

Robustness note: real DNS logs used for training are not guaranteed to be
attack-free (that's the whole problem -- you don't have ground truth in
production). Using the raw mean/stddev as the baseline lets a small amount
of contamination (existing undetected tunneling, or just heavy legitimate
CDN/API traffic with long random-looking subdomains) drag the baseline
upward and blind the detector to exactly what you want it to catch. We use
median + a MAD-based robust standard deviation estimate instead, which is
resistant to up to ~50% contamination -- see robust_baseline().
"""
import argparse
import json
import math
import re
import sys
from collections import Counter

DNS_LINE = re.compile(
    r"^(?P<ts>\S+)\s+queries:\s+client\s+(?P<ip>[0-9a-fA-F.:]+)#\d+:\s+query:\s+(?P<query>\S+)\s+IN"
)


def shannon_entropy(s: str) -> float:
    """Bits/char Shannon entropy. Mirrors EntropyUtil.shannonEntropy in Java."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def average_subdomain_entropy(query: str) -> float:
    """Mirrors EntropyUtil.averageSubdomainEntropy in Java: average entropy
    of every label except the last two (the registrable domain)."""
    labels = query.split(".")
    if len(labels) <= 2:
        return shannon_entropy(labels[0] if labels else "")
    considered = labels[:-2]
    return sum(shannon_entropy(l) for l in considered) / len(considered)


def parse_queries(path: str):
    queries = []
    unparsed = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = DNS_LINE.match(line.strip())
            if not m:
                unparsed += 1
                continue
            queries.append(m.group("query"))
    if unparsed:
        print(f"warning: {unparsed} lines did not match the expected DNS log format and were skipped",
              file=sys.stderr)
    return queries


def robust_baseline(values):
    """Median and MAD-based robust standard deviation estimate.
    1.4826 is the constant that makes MAD a consistent estimator of the
    standard deviation for a normal distribution -- the standard choice for
    a Gaussian-equivalent robust scale estimate."""
    values = sorted(values)
    n = len(values)
    median = values[n // 2] if n % 2 == 1 else (values[n // 2 - 1] + values[n // 2]) / 2
    abs_devs = sorted(abs(v - median) for v in values)
    mad = abs_devs[n // 2] if n % 2 == 1 else (abs_devs[n // 2 - 1] + abs_devs[n // 2]) / 2
    robust_std = 1.4826 * mad
    return median, robust_std


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", required=True, help="path to a DNS query log file (or several, comma-separated)")
    parser.add_argument("--output", required=True, help="path to write the trained model JSON")
    parser.add_argument("--z-score-threshold", type=float, default=None,
                         help="override the auto-selected z-score threshold")
    parser.add_argument("--min-queries-per-window", type=int, default=8)
    parser.add_argument("--window-size-ms", type=int, default=60_000)
    args = parser.parse_args()

    all_queries = []
    for path in args.input.split(","):
        all_queries.extend(parse_queries(path.strip()))

    if len(all_queries) < 100:
        print(f"error: only found {len(all_queries)} parseable DNS queries; need at least 100 for a stable baseline",
              file=sys.stderr)
        sys.exit(1)

    entropies = [average_subdomain_entropy(q) for q in all_queries]

    median, robust_std = robust_baseline(entropies)
    mean = sum(entropies) / len(entropies)

    # A fixed threshold works fine for a single trained model, but if you
    # rerun this on your own traffic and it's over- or under-alerting,
    # this is the number to tune first, or pass --z-score-threshold to
    # force it without touching the statistics above.
    z_threshold = args.z_score_threshold if args.z_score_threshold is not None else 2.0

    model = {
        "baselineMeanEntropy": round(median, 4),  # named "Mean" to match the Java field; we use the robust median as our point estimate
        "baselineStdEntropy": round(robust_std, 4),
        "zScoreThreshold": z_threshold,
        "minQueriesPerWindow": args.min_queries_per_window,
        "windowSizeMillis": args.window_size_ms,
    }

    with open(args.output, "w") as f:
        json.dump(model, f, indent=2)

    print(f"trained on {len(all_queries)} queries from {args.input}")
    print(f"  arithmetic mean entropy:  {mean:.4f} bits/char")
    print(f"  robust median entropy:    {median:.4f} bits/char")
    print(f"  robust std (MAD-based):   {robust_std:.4f} bits/char")
    print(f"  z-score threshold:        {z_threshold}")
    print(f"  -> flags queries/windows with mean entropy >= {median + z_threshold * robust_std:.4f} bits/char")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
