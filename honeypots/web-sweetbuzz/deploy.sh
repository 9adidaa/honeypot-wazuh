#!/bin/bash
# Deployment script for NIX01 VM
echo "Setting up Honey Pot Web App on NIX01..."
sudo apt update && sudo apt install -y python3 python3-pip python3-venv

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional: Run as systemd service
sudo bash -c 'cat << EOF > /etc/systemd/system/honeypot.service
[Unit]
Description=Honey Pot Vulnerable Web App
After=network.target

[Service]
User=nix01
WorkingDirectory=/home/nix01/honeypot_app
ExecStart=/home/nix01/honeypot_app/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl daemon-reload
sudo systemctl enable honeypot
sudo systemctl start honeypot
echo "Honey Pot App deployed and running on port 5000!"
