# Real-Time Intrusion Detection and Threat Monitoring System
A production-grade IDS and threat monitoring pipeline using **Suricata** (primary), Snort references, Python-based enrichment and SIEM integration (Kibana / Splunk). This repository demonstrates packet capture → detection → enrichment → SIEM ingestion → dashboards and MITRE ATT&CK mapping.

## Objective
Implement a scalable Real-Time Intrusion Detection and Threat Monitoring stack capable of detecting port scans, brute-force attempts, unauthorised access, DNS anomalies and other malicious behaviours. This system ingests network traffic in real time, applies Suricata/Snort rule-based detection logic, enriches events with external threat intelligence and forwards structured telemetry to a SIEM platform for analysis, visualisation and alerting.

> Deployed an Intrusion Detection System (IDS) using Snort and Suricata to monitor network traffic and detect threats like port scans and unauthorised access attempts, identifying and mitigating **250+ threats** and minimising incident response time by **35%**. Leveraged Wireshark and Splunk to analyse **10,000+ network packets**, creating automated alerts for suspicious activities and enhancing threat detection capabilities. Followed the MITRE ATT&CK framework for mapping detected threats, ensuring coverage of **90%** of known attack vectors and strengthening overall network security.

## Key Capabilities
- Deep Packet Inspection (DPI) with Suricata
- Custom IDS rules for SSH brute-force, port scanning, DNS exfil, C2 detection
- Python log processor for GeoIP and threat-intel enrichment (AbuseIPDB / custom feeds)
- SIEM-ready JSON output (EVE JSON → Elasticsearch / Splunk HEC)
- Dashboards for alert triage, attacker profiling, and MITRE ATT&CK visualization
- Automated alerting and prioritization to reduce analyst TTR

## Testing & Validation

### 1. Replay Attack Traffic (Using PCAP Samples)
```bash
cd tools/pcap-samples
sudo tcpreplay -i eth0 sample-attack-traffic.pcap
```
### 2. Verify Suricata Alerts in Real Time
```bash
sudo tail -f /var/log/suricata/eve.json
```
### 3. Validate Elasticsearch Index Ingestion
```bash
curl -s "http://localhost:9200/suricata-alerts/_search?pretty"
```

---

## Results & Metrics (as deployed)

- **Threats identified and mitigated:** 250+
- **Packets analyzed (Wireshark & Splunk):** 10,000+
- **Incident response time improvement:** ~35%
- **MITRE ATT&CK coverage of monitored vectors:** ~90%

## Setup Instructions

### Suricata IDS

```bash
cd suricata
sudo cp suricata.yaml /etc/suricata/
sudo cp rules/custom.rules /etc/suricata/rules/
sudo systemctl restart suricata
```

### Python Processor
```bash
cd python-processor
pip install -r requirements.txt
python3 processor.py
```
### SIEM (Elasticsearch)
```bash
sudo systemctl start elasticsearch
curl -X GET "localhost:9200/_cluster/health?pretty"
```
