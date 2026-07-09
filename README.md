📁 Project 23 – DNS Tunneling Detector (Traffic Analysis)

Description
Sniffs DNS queries in real time, computes entropy of subdomain labels, and alerts on high entropy (possible tunneling) and high query rates.

Key Features

    Sniffs UDP port 53 with Scapy.

    Calculates Shannon entropy for each label.

    Alerts when entropy > threshold.

    Alerts when query rate > threshold per client.

    Logs alerts to dns_alerts.log.

Technologies

    Scapy, math.

Prerequisites

    Python 3, Scapy, root privileges for sniffing.

Installation
bash

pip install scapy

Usage
bash

sudo python dns_tunnel_detector.py

Sample Output
text

[!] ALERT: High entropy DNS query from 192.168.1.10: abcdefghijklmnopqrstuvwxyz0123456789.test.com (entropy 4.87)
[!] ALERT: High DNS query rate from xxx.xxx.x.xx: 11 queries in 5s

Notes

    Adjust ENTROPY_THRESHOLD and RATE_THRESHOLD in the script.

    Test with nslookup of a long random domain.
