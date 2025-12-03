#!/usr/bin/env python3
import json
import time
import datetime
import os
import requests
from elasticsearch import Elasticsearch

EVE_PATH = os.getenv("EVE_PATH", "../suricata/eve.json")
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
INDEX = os.getenv("ES_INDEX", "suricata-alerts")
TI_API_KEY = os.getenv("TI_API_KEY", "")

es = Elasticsearch(ES_HOST)

def enrich_with_threat_intel(ip):
    if not TI_API_KEY:
        return {}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": TI_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        return resp.json().get("data", {})
    except:
        return {}

def mitre_map(signature):
    try:
        with open("mitre_mapping.json") as fh:
            mapping = json.load(fh)
        return mapping.get(signature, [])
    except:
        return []

def process_event(event):
    alert = event.get("alert", {})
    src = event.get("src_ip")

    doc = {
        "timestamp": event.get("timestamp"),
        "src_ip": src,
        "dest_ip": event.get("dest_ip"),
        "protocol": event.get("proto"),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "flow": event.get("flow", {}),
        "processed_at": datetime.datetime.utcnow().isoformat(),
        "payload": event.get("payload", None),
        "threat_intel": enrich_with_threat_intel(src) if src else {},
        "mitre": mitre_map(alert.get("signature", ""))
    }

    es.index(index=INDEX, document=doc)

def tail_eve(path):
    with open(path, "r") as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                evt = json.loads(line)
                if evt.get("event_type") == "alert":
                    process_event(evt)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    tail_eve(EVE_PATH)
