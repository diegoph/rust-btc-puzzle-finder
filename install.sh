#!/bin/bash

sudo apt-get install -y build-essential
curl https://sh.rustup.rs -sSf | sh -s -- -y

#make
#NUM_THREADS=$(($(nproc) - 1))

source "$HOME/.cargo/env"

cargo build --release

SERVICE_FILE=/etc/systemd/system/keyhunt.service

echo "[Unit]
Description=Meu Keyhunt
After=network.target

[Service]
WorkingDirectory=/opt/hunt   
ExecStart=/opt/hunt/target/release/btc_key_checker --carteira=68                                   
StandardOutput=append:/opt/hunt/log-service-output.log
StandardError=append:/opt/hunt/log-service-err.log

[Install]
WantedBy=multi-user.target" | sudo tee $SERVICE_FILE

sudo chmod 644 $SERVICE_FILE

sudo systemctl daemon-reload
sudo systemctl enable keyhunt.service
sudo systemctl stop keyhunt.service
sudo systemctl start keyhunt.service

sudo systemctl status keyhunt.service