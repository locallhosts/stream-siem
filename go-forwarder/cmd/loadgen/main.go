// Command loadgen writes synthetic auth/dns/firewall log lines to files,
// mimicking real log formats, at a configurable rate. It deliberately plants
// a small number of beaconing sources and a DNS-tunneling source so you can
// verify the Flink detectors actually fire against known ground truth,
// rather than eyeballing benign traffic and hoping something lights up.
//
// Usage:
//
//	loadgen -rate 2000 -duration 10m -out-dir ./synthetic-logs
package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

var (
	rate     = flag.Int("rate", 1000, "target events per second across all source types")
	duration = flag.Duration("duration", 5*time.Minute, "how long to run")
	outDir   = flag.String("out-dir", "./synthetic-logs", "directory to write auth.log, dns.log, firewall.log")
	seed     = flag.Int64("seed", 42, "PRNG seed, for reproducible runs")
)

var benignIPs = []string{
	"10.0.1.12", "10.0.1.45", "10.0.1.88", "10.0.2.14", "10.0.2.77",
	"10.0.3.5", "10.0.3.61", "10.0.4.23", "10.0.4.99", "10.0.5.31",
}

// beaconIPs are the "malware" sources: they call out at a fixed interval
// with low jitter, which is exactly the signature the Flink beaconing
// detector (low-variance inter-arrival time per source IP) should flag.
var beaconIPs = []string{"10.0.6.200", "10.0.6.201"}

var tunnelIP = "10.0.7.50" // plants a high-entropy DNS query volume from one host

var users = []string{"alice", "bob", "carol", "dave", "erin", "frank", "svc-backup", "svc-monitor"}

var domains = []string{
	"example.com", "internal.corp", "api.example.com", "cdn.example.net",
	"mail.example.com", "vpn.example.com",
}

func main() {
	flag.Parse()
	rng := rand.New(rand.NewSource(*seed))

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("creating out dir: %v", err)
	}
	authF, err := os.Create(filepath.Join(*outDir, "auth.log"))
	if err != nil {
		log.Fatal(err)
	}
	defer authF.Close()
	dnsF, err := os.Create(filepath.Join(*outDir, "dns.log"))
	if err != nil {
		log.Fatal(err)
	}
	defer dnsF.Close()
	fwF, err := os.Create(filepath.Join(*outDir, "firewall.log"))
	if err != nil {
		log.Fatal(err)
	}
	defer fwF.Close()

	log.Printf("generating ~%d events/sec for %s into %s (seed=%d)", *rate, *duration, *outDir, *seed)
	log.Printf("planted beaconing sources: %v", beaconIPs)
	log.Printf("planted DNS-tunneling source: %s", tunnelIP)

	stop := time.Now().Add(*duration)
	tickInterval := time.Second / time.Duration(*rate)
	if tickInterval <= 0 {
		tickInterval = time.Millisecond
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	// Fixed beacon interval; low jitter is the point.
	beaconInterval := 30 * time.Second
	nextBeacon := make(map[string]time.Time, len(beaconIPs))
	now := time.Now()
	for _, ip := range beaconIPs {
		nextBeacon[ip] = now.Add(beaconInterval)
	}

	eventCount := 0
	for now := range ticker.C {
		if now.After(stop) {
			break
		}
		eventCount++

		switch r := rng.Float64(); {
		case r < 0.4:
			writeAuthLine(authF, rng, now)
		case r < 0.75:
			writeDNSLine(dnsF, rng, now, false)
		default:
			writeFirewallLine(fwF, rng, now)
		}

		// Beaconing: independent of the main rate loop, fires close to its
		// fixed interval with a small jitter (±1.5s) — realistic enough to
		// not be a perfectly flat line, but well inside the variance
		// threshold a beaconing detector should use.
		for _, ip := range beaconIPs {
			if now.After(nextBeacon[ip]) {
				jitter := time.Duration(rng.Intn(3000)-1500) * time.Millisecond
				writeFirewallBeacon(fwF, ip, now)
				nextBeacon[ip] = now.Add(beaconInterval + jitter)
			}
		}

		// DNS tunneling: bursts of high-entropy subdomain queries from one host.
		if rng.Float64() < 0.05 {
			writeDNSLine(dnsF, rng, now, true)
		}
	}

	log.Printf("done: wrote %d events", eventCount)
}

func writeAuthLine(f *os.File, rng *rand.Rand, ts time.Time) {
	user := users[rng.Intn(len(users))]
	ip := benignIPs[rng.Intn(len(benignIPs))]
	success := rng.Float64() > 0.08 // ~8% failure rate baseline
	var msg string
	if success {
		msg = fmt.Sprintf("%s sshd[%d]: Accepted publickey for %s from %s port %d ssh2",
			ts.Format(time.Stamp), 1000+rng.Intn(9000), user, ip, 20000+rng.Intn(40000))
	} else {
		msg = fmt.Sprintf("%s sshd[%d]: Failed password for %s from %s port %d ssh2",
			ts.Format(time.Stamp), 1000+rng.Intn(9000), user, ip, 20000+rng.Intn(40000))
	}
	fmt.Fprintln(f, msg)
}

func randomHexLabel(rng *rand.Rand, n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[rng.Intn(len(hex))]
	}
	return string(b)
}

func writeDNSLine(f *os.File, rng *rand.Rand, ts time.Time, tunneling bool) {
	ip := benignIPs[rng.Intn(len(benignIPs))]
	domain := domains[rng.Intn(len(domains))]
	query := domain
	if tunneling {
		ip = tunnelIP
		// High-entropy subdomain labels are the classic DNS-tunneling
		// signature: data smuggled out encoded into query names.
		query = fmt.Sprintf("%s.%s.exfil.badhost.net", randomHexLabel(rng, 32), randomHexLabel(rng, 32))
	}
	fmt.Fprintf(f, "%s queries: client %s#%d: query: %s IN A + (10.0.0.1)\n",
		ts.Format(time.RFC3339), ip, 30000+rng.Intn(20000), query)
}

func writeFirewallLine(f *os.File, rng *rand.Rand, ts time.Time) {
	src := benignIPs[rng.Intn(len(benignIPs))]
	dst := fmt.Sprintf("203.0.113.%d", rng.Intn(255))
	port := []int{443, 80, 22, 53, 8443}[rng.Intn(5)]
	fmt.Fprintf(f, "%s ALLOW TCP src=%s dst=%s dport=%d\n", ts.Format(time.RFC3339), src, dst, port)
}

func writeFirewallBeacon(f *os.File, ip string, ts time.Time) {
	// Fixed C2-ish destination and port — the interval regularity, not the
	// destination, is what the detector should key on.
	fmt.Fprintf(f, "%s ALLOW TCP src=%s dst=198.51.100.77 dport=443\n", ts.Format(time.RFC3339), ip)
}
