#!/usr/bin/env python3
import json
import time
import datetime
import os
import requests
from elasticsearch import Elasticsearch

CONFIG_PATH = "config.json"

# Load config
with open(CONFIG_PATH) as fh:
    cfg = json.load(fh)

EVE_PATH = cfg["EVE_PATH"]
ES_HOST = cfg["ELASTICSEARCH_HOST"]
ES_INDEX = cfg["ELASTICSEARCH_INDEX"]
TI_API_KEY = cfg["THREAT_INTEL_API_KEY"]

es = Elasticsearch(ES_HOST)

def enrich_with_threat_intel(ip):
    if not TI_API_KEY or not ip:
        return {}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": TI_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        return r.json().get("data", {})
    except Exception:
        return {}

def mitre_map(signature):
    try:
        with open("mitre_mapping.json") as fh:
            mapping = json.load(fh)
        return mapping.get(signature, [])
    except:
        return []

def process_alert(event):
    alert = event.get("alert", {})
    src_ip = event.get("src_ip")

    doc = {
        "timestamp": event.get("timestamp"),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "src_ip": src_ip,
        "dest_ip": event.get("dest_ip"),
        "proto": event.get("proto"),
        "flow": event.get("flow"),
        "threat_intel": enrich_with_threat_intel(src_ip),
        "mitre": mitre_map(alert.get("signature")),
        "processed_at": datetime.datetime.utcnow().isoformat()
    }

    es.index(index=ES_INDEX, document=doc)
    print(f"[+] Indexed alert: {alert.get('signature')} from {src_ip}")

def tail_eve(path):
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    process_alert(event)
            except:
                continue

if __name__ == "__main__":
    print("[*] Real-time processor started...")
    tail_eve(EVE_PATH)
