#!/usr/bin/env python3
"""Local pipeline smoke test: a pure-Python, single-process port of the
logic in flink-job/src/main/java/com/siem/{parse,functions}/*.java.

WHY THIS EXISTS: Flink itself needs a JVM, Maven Central, and (per
docker-compose.yml) Kafka + ClickHouse containers -- real infrastructure
that isn't always at hand (e.g. sandboxed CI, a laptop with Docker turned
off, this project's own offline dev environment). This script gives you a
five-second way to validate three things for real, without any of that:

  1. The parser regexes actually match your log format
  2. The detector thresholds actually fire on your planted attack patterns
     (or don't fire on benign traffic -- false positives matter too)
  3. The ClickHouse schema actually accepts what the detectors produce

It is NOT a substitute for running the real Flink job. It processes events
in a single sorted-by-timestamp pass rather than Flink's watermark-driven,
partitioned, checkpointed execution, so it says nothing about the things
that only show up under real concurrency, real out-of-order delivery
across Kafka partitions, or a restart-and-recover cycle. Treat a clean run
here as "the algorithm is right"; treat the Flink job in production as the
place correctness under real distributed execution is actually proven.

Usage:
    python3 tools/local_pipeline_smoke_test.py \
        --auth-log /path/to/auth.log \
        --dns-log /path/to/dns.log \
        --firewall-log /path/to/firewall.log \
        --model-params /path/to/model_params.json \
        --clickhouse-insert   # optional: also load results into ClickHouse

Mirrors, field-for-field and threshold-for-threshold:
  - AuthLogParser.java, DnsLogParser.java, FirewallLogParser.java
  - FailedLoginRateDetector.java (5-min tumbling window, threshold count)
  - BeaconingDetector.java (coefficient-of-variation on inter-arrival times)
  - DnsTunnelingDetector.java (z-score against an offline-trained baseline)
"""
import argparse
import json
import math
import re
import subprocess
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone

AUTH_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+sshd\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F.:]+)\s+port\s+(?P<port>\d+)"
)
DNS_PATTERN = re.compile(
    r"^(?P<ts>\S+)\s+queries:\s+client\s+(?P<ip>[0-9a-fA-F.:]+)#\d+:\s+query:\s+(?P<query>\S+)\s+IN"
)
FW_PATTERN = re.compile(
    r"^(?P<ts>\S+)\s+(?P<action>ALLOW|DENY)\s+(?P<proto>\S+)\s+src=(?P<src>[0-9a-fA-F.:]+)\s+dst=(?P<dst>[0-9a-fA-F.:]+)\s+dport=(?P<port>\d+)"
)


def parse_auth(line, year):
    m = AUTH_PATTERN.match(line)
    if not m:
        return None
    dt = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    return {
        "source_type": "auth", "event_time": dt, "source_ip": m.group("ip"),
        "user": m.group("user"), "auth_success": m.group("result") == "Accepted",
        "raw": line,
    }


def parse_dns(line):
    m = DNS_PATTERN.match(line)
    if not m:
        return None
    dt = datetime.fromisoformat(m.group("ts").replace("Z", "+00:00"))
    return {"source_type": "dns", "event_time": dt, "source_ip": m.group("ip"), "dns_query": m.group("query"), "raw": line}


def parse_firewall(line):
    m = FW_PATTERN.match(line)
    if not m:
        return None
    dt = datetime.fromisoformat(m.group("ts").replace("Z", "+00:00"))
    return {
        "source_type": "firewall", "event_time": dt, "source_ip": m.group("src"),
        "dest_ip": m.group("dst"), "dest_port": int(m.group("port")), "action": m.group("action"),
        "raw": line,
    }


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = defaultdict(int)
    for c in s:
        counts[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def average_subdomain_entropy(query):
    labels = query.split(".")
    if len(labels) <= 2:
        return shannon_entropy(labels[0] if labels else "")
    considered = labels[:-2]
    return sum(shannon_entropy(l) for l in considered) / len(considered)


def detect_failed_login_rate(auth_events, threshold=10, window_seconds=300):
    """Tumbling window, mirrors FailedLoginRateDetector.java."""
    alerts = []
    by_ip = defaultdict(list)
    for e in auth_events:
        by_ip[e["source_ip"]].append(e)
    for ip, events in by_ip.items():
        events.sort(key=lambda e: e["event_time"])
        if not events:
            continue
        window_start = events[0]["event_time"]
        bucket = []
        for e in events:
            if (e["event_time"] - window_start).total_seconds() >= window_seconds:
                alerts.extend(_flush_login_window(ip, window_start, bucket, threshold))
                window_start = e["event_time"]
                bucket = []
            bucket.append(e)
        alerts.extend(_flush_login_window(ip, window_start, bucket, threshold))
    return alerts


def _flush_login_window(ip, window_start, bucket, threshold):
    failed = sum(1 for e in bucket if not e["auth_success"])
    if failed >= threshold:
        window_end = max(e["event_time"] for e in bucket)
        return [{
            "alert_type": "failed_login_rate", "detected_at": window_end,
            "window_start": window_start, "window_end": window_end,
            "source_ip": ip, "dest_ip": None, "source_type": "auth",
            "score": min(1.0, failed / (threshold * 3)),
            "details": f"{failed} failed logins (of {len(bucket)} total) from {ip} in a 5-minute window (threshold={threshold})",
        }]
    return []


def detect_beaconing(firewall_events, max_samples=20, min_samples=5, max_cv=0.15,
                      min_interval_s=5, max_interval_s=3600):
    """Mirrors BeaconingDetector.java's sliding-buffer coefficient-of-variation logic."""
    alerts = []
    allow_events = [e for e in firewall_events if e.get("action") == "ALLOW"]
    by_channel = defaultdict(list)
    for e in allow_events:
        by_channel[(e["source_ip"], e["dest_ip"])].append(e)

    for (src, dst), events in by_channel.items():
        events.sort(key=lambda e: e["event_time"])
        buf = deque(maxlen=max_samples)
        last_alert = None
        for e in events:
            buf.append(e["event_time"])
            if len(buf) < min_samples:
                continue
            ts = sorted(buf)
            intervals = [(ts[i] - ts[i - 1]).total_seconds() for i in range(1, len(ts))]
            mean = sum(intervals) / len(intervals)
            variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            stddev = math.sqrt(variance)
            cv = stddev / mean if mean > 0 else float("inf")
            if cv <= max_cv and min_interval_s <= mean <= max_interval_s:
                cooldown = mean * 3
                if last_alert is None or (e["event_time"] - last_alert).total_seconds() >= cooldown:
                    alerts.append({
                        "alert_type": "beaconing", "detected_at": e["event_time"],
                        "window_start": ts[0], "window_end": e["event_time"],
                        "source_ip": src, "dest_ip": dst, "source_type": "firewall",
                        "score": max(0.0, 1.0 - cv),
                        "details": f"{len(buf)} outbound connections to {dst} at ~{mean:.1f}s intervals "
                                   f"(coefficient of variation={cv:.3f}, threshold={max_cv})",
                    })
                    last_alert = e["event_time"]
    return alerts


def detect_dns_tunneling(dns_events, model, window_seconds=60):
    """Mirrors DnsTunnelingDetector.java's single-pass mean/variance accumulator."""
    alerts = []
    by_ip = defaultdict(list)
    for e in dns_events:
        by_ip[e["source_ip"]].append(e)

    for ip, events in by_ip.items():
        events.sort(key=lambda e: e["event_time"])
        if not events:
            continue
        window_start = events[0]["event_time"]
        bucket = []
        for e in events:
            if (e["event_time"] - window_start).total_seconds() >= window_seconds:
                alerts.extend(_flush_dns_window(ip, window_start, bucket, model))
                window_start = e["event_time"]
                bucket = []
            bucket.append(e)
        alerts.extend(_flush_dns_window(ip, window_start, bucket, model))
    return alerts


def _flush_dns_window(ip, window_start, bucket, model):
    if len(bucket) < model["minQueriesPerWindow"]:
        return []
    entropies = [average_subdomain_entropy(e["dns_query"]) for e in bucket]
    mean_entropy = sum(entropies) / len(entropies)
    baseline_mean = model["baselineMeanEntropy"]
    baseline_std = model["baselineStdEntropy"]
    z = (mean_entropy - baseline_mean) / baseline_std if baseline_std > 0 else 0
    if z >= model["zScoreThreshold"]:
        window_end = max(e["event_time"] for e in bucket)
        score = min(1.0, z / (model["zScoreThreshold"] * 2))
        return [{
            "alert_type": "dns_tunneling", "detected_at": window_end,
            "window_start": window_start, "window_end": window_end,
            "source_ip": ip, "dest_ip": None, "source_type": "dns",
            "score": score,
            "details": f"{len(bucket)} DNS queries from {ip}, mean subdomain entropy {mean_entropy:.2f} bits/char "
                       f"(baseline {baseline_mean:.2f} +/- {baseline_std:.2f}, z-score {z:.2f}, "
                       f"threshold {model['zScoreThreshold']}). Example query: {bucket[-1]['dns_query']}",
        }]
    return []


def load_events(auth_path, dns_path, fw_path):
    year = datetime.now(timezone.utc).year
    auth, dns, fw = [], [], []
    if auth_path:
        with open(auth_path, errors="replace") as f:
            for line in f:
                e = parse_auth(line.strip(), year)
                if e:
                    auth.append(e)
    if dns_path:
        with open(dns_path, errors="replace") as f:
            for line in f:
                e = parse_dns(line.strip())
                if e:
                    dns.append(e)
    if fw_path:
        with open(fw_path, errors="replace") as f:
            for line in f:
                e = parse_firewall(line.strip())
                if e:
                    fw.append(e)
    return auth, dns, fw


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--auth-log")
    p.add_argument("--dns-log")
    p.add_argument("--firewall-log")
    p.add_argument("--model-params", required=True)
    p.add_argument("--clickhouse-insert", action="store_true",
                    help="also load parsed events + alerts into the local `siem` ClickHouse database via clickhouse-client")
    args = p.parse_args()

    with open(args.model_params) as f:
        model = json.load(f)

    auth, dns, fw = load_events(args.auth_log, args.dns_log, args.firewall_log)
    print(f"parsed: {len(auth)} auth, {len(dns)} dns, {len(fw)} firewall events", file=sys.stderr)

    failed_login_alerts = detect_failed_login_rate(auth)
    beaconing_alerts = detect_beaconing(fw)
    dns_alerts = detect_dns_tunneling(dns, model)
    all_alerts = failed_login_alerts + beaconing_alerts + dns_alerts
    all_alerts.sort(key=lambda a: a["detected_at"])

    print(f"\n{len(all_alerts)} alerts:", file=sys.stderr)
    for a in all_alerts:
        print(f"  [{a['alert_type']:>18}] {a['source_ip']:>15} -> {a.get('dest_ip') or '-':<15} "
              f"score={a['score']:.2f}  {a['details']}", file=sys.stderr)

    if args.clickhouse_insert:
        insert_into_clickhouse(auth + dns + fw, all_alerts)

    print(json.dumps({
        "auth_events": len(auth), "dns_events": len(dns), "firewall_events": len(fw),
        "alerts_by_type": {
            "failed_login_rate": len(failed_login_alerts),
            "beaconing": len(beaconing_alerts),
            "dns_tunneling": len(dns_alerts),
        },
    }))


def ch_escape(s):
    if s is None:
        return "NULL"
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _run_batched_inserts(table_sql_prefix, rows, batch_size=2000):
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        sql = table_sql_prefix + ",".join(batch)
        # Feed via stdin rather than argv: bulk VALUES lists blow past the
        # OS's argument-length limit (ARG_MAX) well before ClickHouse's own
        # query-size limit -- `clickhouse-client --query "<huge sql>"` fails
        # with "Argument list too long" once you're inserting tens of
        # thousands of rows in one statement, which this script's first
        # draft did. Piping to stdin and batching in chunks fixes both the
        # OS limit and keeps any single request reasonably sized.
        subprocess.run(["clickhouse-client", "--multiquery"], input=sql.encode(), check=True)


def insert_into_clickhouse(events, alerts):
    rows = []
    for e in events:
        rows.append("({}, {}, {}, {}, {}, {}, {}, {}, {}, {})".format(
            f"'{e['event_time'].strftime('%Y-%m-%d %H:%M:%S')}'",
            ch_escape(e["source_type"]), ch_escape(e["source_ip"]),
            ch_escape(e.get("dest_ip")), e.get("dest_port") if e.get("dest_port") is not None else "NULL",
            ch_escape(e.get("user")),
            (1 if e.get("auth_success") else 0) if "auth_success" in e else "NULL",
            ch_escape(e.get("dns_query")), ch_escape("smoke-test-host"), ch_escape(e["raw"][:500]),
        ))
    if rows:
        prefix = ("INSERT INTO siem.enriched_events (event_time, source_type, source_ip, dest_ip, dest_port, "
                   "user, auth_success, dns_query, host, raw) VALUES ")
        _run_batched_inserts(prefix, rows)
        print(f"inserted {len(rows)} enriched_events rows into ClickHouse", file=sys.stderr)

    arows = []
    for a in alerts:
        arows.append("({}, {}, {}, {}, {}, {}, {}, {}, {})".format(
            f"'{a['detected_at'].strftime('%Y-%m-%d %H:%M:%S')}'",
            f"'{a['window_start'].strftime('%Y-%m-%d %H:%M:%S')}'",
            f"'{a['window_end'].strftime('%Y-%m-%d %H:%M:%S')}'",
            ch_escape(a["alert_type"]), ch_escape(a["source_type"]), ch_escape(a["source_ip"]),
            ch_escape(a.get("dest_ip")), a["score"], ch_escape(a["details"]),
        ))
    if arows:
        prefix = ("INSERT INTO siem.alerts (detected_at, window_start, window_end, alert_type, source_type, "
                   "source_ip, dest_ip, score, details) VALUES ")
        _run_batched_inserts(prefix, arows)
        print(f"inserted {len(arows)} alerts rows into ClickHouse", file=sys.stderr)


if __name__ == "__main__":
    main()
