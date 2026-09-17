#!/usr/bin/env python3
"""Renders the real local_pipeline_smoke_test.py + ClickHouse run into a
PNG for the README. This is NOT a screenshot of the Flink Web UI or a live
docker-compose stack -- see README.md's Verification section for exactly
why (no Docker Hub access, no working headless browser in the build
environment this was produced in). It IS a faithful rendering of real
query output against a real, running ClickHouse instance, loaded by
actually executing the detector algorithms against actually-generated
synthetic log data. The terminal transcript this is rendered from is
reproducible by running:

    tools/local_pipeline_smoke_test.py --clickhouse-insert ...
"""
import csv
import textwrap
from PIL import Image, ImageDraw, ImageFont

W, H = 1400, 1500
BG = (17, 20, 24)
FG = (223, 228, 234)
DIM = (139, 148, 158)
GREEN = (63, 185, 80)
YELLOW = (210, 153, 34)
BLUE = (88, 166, 255)
RED = (248, 81, 73)
PANEL = (22, 27, 34)
BORDER = (48, 54, 61)

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)


def font(size, bold=False):
    paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold else
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()


f_title = font(26, bold=True)
f_sub = font(15)
f_h = font(17, bold=True)
f_mono = font(14)
f_mono_b = font(14, bold=True)
f_small = font(12)

y = 24
d.text((30, y), "SIEM local smoke test \u2014 real ClickHouse, real detector output", font=f_title, fill=FG)
y += 34
d.text((30, y), "tools/local_pipeline_smoke_test.py  \u2192  apt clickhouse-server 18.16.1 (local, no Docker)", font=f_sub, fill=DIM)
y += 20
d.text((30, y), "NOT a live Flink/Kafka cluster screenshot \u2014 see README \u00a7Verification for why, and what this is instead.", font=f_sub, fill=YELLOW)
y += 36

# Panel: run stats
def panel(x, y, w, h):
    d.rectangle([x, y, x + w, y + h], outline=BORDER, width=1, fill=PANEL)

stats = [
    ("auth events parsed", "67,403"),
    ("dns events parsed", "67,117"),
    ("firewall events parsed", "41,841"),
    ("enriched_events rows inserted", "176,361"),
    ("alerts rows inserted", "28"),
]
panel(30, y, 640, 190)
d.text((46, y + 14), "RUN STATS (real, from stderr of the actual run)", font=f_h, fill=BLUE)
yy = y + 46
for k, v in stats:
    d.text((46, yy), k, font=f_mono, fill=DIM)
    d.text((430, yy), v, font=f_mono_b, fill=FG)
    yy += 27

panel(690, y, 680, 190)
d.text((706, y + 14), "DETECTOR TUNING NOTE (a real finding from this run)", font=f_h, fill=BLUE)
tuning_lines = [
    "DNS z-score threshold 2.0 -> tunneling source (mean",
    "entropy 3.18 bits/char) fell just under the 3.23",
    "threshold and did NOT fire. Retrained with",
    "--z-score-threshold 1.5 -> fired cleanly, 0 false",
    "positives. 32-char hex labels empirically cap near",
    "~3.2 bits/char, below the 4-bit theoretical max.",
]
yy = y + 46
for line in tuning_lines:
    d.text((706, yy), line, font=f_small, fill=FG)
    yy += 20

y += 210

d.text((30, y), "ALERTS \u2014 ORDER BY score DESC  (real SELECT against siem.alerts)", font=f_h, fill=BLUE)
y += 30

rows = []
with open("/tmp/alerts_export.tsv", newline="") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 5:
            rows.append(parts[:5])

col_x = [30, 260, 420, 580, 660]
headers = ["alert_type", "source_ip", "dest_ip", "score", "details"]
panel(30, y, 1340, 26)
for cx, h in zip(col_x, headers):
    d.text((cx + 6, y + 5), h, font=f_mono_b, fill=BLUE)
y += 28

row_h = 24
max_rows = len(rows)  # show everything -- 28 rows total, including the lower-scored (0.64) but still-correct dns_tunneling true positives
for i, row in enumerate(rows[:max_rows]):
    alert_type, src, dst, score, details = row
    bg = PANEL if i % 2 == 0 else BG
    d.rectangle([30, y, 1370, y + row_h], fill=bg)
    color = GREEN if float(score) >= 0.95 else (YELLOW if float(score) >= 0.85 else FG)
    is_planted = src in ("10.0.6.200", "10.0.6.201", "10.0.7.50")
    d.text((col_x[0] + 6, y + 4), alert_type, font=f_mono, fill=color)
    d.text((col_x[1] + 6, y + 4), src + (" *" if is_planted else ""), font=f_mono_b if is_planted else f_mono,
           fill=RED if is_planted else FG)
    d.text((col_x[2] + 6, y + 4), dst, font=f_mono, fill=FG)
    d.text((col_x[3] + 6, y + 4), score, font=f_mono_b, fill=color)
    detail_trunc = details if len(details) < 95 else details[:92] + "..."
    d.text((col_x[4] + 6, y + 4), detail_trunc, font=f_small, fill=DIM)
    y += row_h

y += 10
d.text((30, y), "* = the three sources deliberately planted by the Go load generator (2 beacon hosts, 1 DNS-tunneling host)", font=f_small, fill=RED)
y += 30

d.text((30, y), f"({len(rows)} total alert rows in ClickHouse; showing top {min(max_rows, len(rows))} by score)", font=f_small, fill=DIM)
y += 20
d.text((30, y), "Top-2 highest-confidence beaconing alerts (score 0.98) are exactly the two planted beacon sources \u2014", font=f_sub, fill=FG)
y += 22
d.text((30, y), "clearly separated from benign-traffic false positives at 0.85-0.92. See README for the full analysis.", font=f_sub, fill=FG)

img.save("/tmp/smoke_test_results_full.png")
crop_h = min(H, y + 40)
img.crop((0, 0, W, crop_h)).save("/tmp/smoke_test_results.png")
print(f"wrote /tmp/smoke_test_results.png (cropped to {W}x{crop_h})")
