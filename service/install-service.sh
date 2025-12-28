#!/bin/bash

sudo cp processor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable processor
sudo systemctl start processor

echo "[+] Service installed and running."

