#!/bin/bash

echo "[*] Checking EVE log..."
sudo tail -n 20 /var/log/suricata/eve.json

echo "[*] Checking Elasticsearch..."
curl -s "http://localhost:9200/suricata-alerts/_search?pretty"
