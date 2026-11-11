# README

# Network Packet Sniffer and Log Analyser

Status: Planned (In Development)

## Project Overview
A lightweight, modular command-line tool built with Python to capture, unpack, and inspect raw IPv4 packets (TCP, UDP, ICMP) and correlate network events with web server access logs to detect anomalous authentication surges.

---

## Key Features
- Real-Time Packet Capture: Decodes Ethernet, IPv4, TCP, and UDP headers using raw sockets.
- Protocol Filtering: Filter captured packets by protocol, target port, or specific source/destination IP.
- Log Correlation Engine: Parses Apache/Nginx access logs with regex to identify repeated authentication alerts.
- Structured Export: Dumps session packet statistics and security alert thresholds to JSON and CSV formats.
- Automated Test Suite: Built with Python's native unittest framework to validate protocol decoding against sample packet data.

---

## Technologies Used
- Language: Python 3.12
- Core Standard Modules: socket, struct, re, argparse, unittest, json, csv
- Development Environment: Linux (Ubuntu 24.04 LTS / Debian)
- Version Control: Git and GitHub

---

## Getting Started

### Prerequisites
- Python 3.10 or higher installed
- Linux operating system with administrative packet capture privileges

### Installation & Execution
1. Clone this repository:
   git clone [Your Repository URL]
   cd network-packet-sniffer

2. Run the packet sniffer on default interface:
   python3 sniffer.py --interface eth0 --count 50

3. Filter specifically for TCP traffic on Port 80/443:
   python3 sniffer.py --protocol tcp --port 443

4. Parse web server log file for authentication anomalies:
   python3 sniffer.py --analyze-log /var/log/nginx/access.log --threshold 10

5. Run automated test suite:
   python3 -m unittest discover tests/

---

## Known Limitations & Planned Enhancements
- Current Limitation: Raw socket sniffing is optimized for Linux operating systems.
- Planned Enhancement: Integrate Scapy for cross-platform packet parsing and implement pcap file replaying by May 2027.

---

## Author & Academic Affiliation
- Author: Gyanshu Raj (Registration Number: 12622202)
- Programme: B.Tech Computer Science and Engineering (Cyber Security), Lovely Professional University
- Leadership: Founding Director, Cyber Security Club
- License: Distributed under the MIT License.
--------------------------------------------------------------------------------------------------------------------------------------------
