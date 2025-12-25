#!/bin/bash
# Replay attack traffic for testing
tcpreplay -i eth0 sample-attack-traffic.pcap
