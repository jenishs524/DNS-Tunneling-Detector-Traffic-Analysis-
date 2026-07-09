#!/usr/bin/env python3
"""
Project 23 – DNS Tunneling Detector
Sniffs DNS queries, computes entropy, and alerts on anomalies.
"""

import time  # <-- ADDED this line
import math
from collections import defaultdict, deque
from scapy.all import sniff, DNS, DNSQR, IP

# ---------- CONFIG ----------
ENTROPY_THRESHOLD = 4.5      # for a label
RATE_THRESHOLD = 10          # queries per 5 seconds
TIME_WINDOW = 5              # seconds
ALERT_LOG = "dns_alerts.log"

# ---------- STATE ----------
client_queries = defaultdict(lambda: deque())  # client -> list of timestamps

def shannon_entropy(label):
    """Compute Shannon entropy of a string."""
    if not label:
        return 0
    prob = [float(label.count(c)) / len(label) for c in set(label)]
    return -sum(p * math.log2(p) for p in prob)

def log_alert(msg):
    with open(ALERT_LOG, 'a') as f:
        f.write(f"{msg}\n")
    print(f"[!] ALERT: {msg}")

def packet_callback(pkt):
    if DNS in pkt and pkt[DNS].qr == 0:  # query
        qname = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
        labels = qname.split('.')
        src_ip = pkt[IP].src

        # 1. Entropy check on each label
        for label in labels:
            if len(label) > 10:   # only check long labels
                e = shannon_entropy(label)
                if e > ENTROPY_THRESHOLD:
                    msg = f"High entropy DNS query from {src_ip}: {qname} (entropy {e:.2f})"
                    log_alert(msg)

        # 2. Rate check per client
        now = time.time()
        qs = client_queries[src_ip]
        qs.append(now)
        # Remove old entries
        while qs and now - qs[0] > TIME_WINDOW:
            qs.popleft()
        if len(qs) > RATE_THRESHOLD:
            msg = f"High DNS query rate from {src_ip}: {len(qs)} queries in {TIME_WINDOW}s"
            log_alert(msg)
            # Reset to avoid repeated alerts
            qs.clear()

if __name__ == "__main__":
    print("[*] DNS Tunneling Detector started. Sniffing UDP port 53...")
    print(f"[*] Entropy threshold: {ENTROPY_THRESHOLD}, rate: {RATE_THRESHOLD}/{TIME_WINDOW}s")
    sniff(filter="udp port 53", prn=packet_callback, store=0)