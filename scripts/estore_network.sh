#!/bin/bash
set -e

echo "[+] Setting up BeaglePlay as WiFi MITM Gateway..."

# Copy configs
sudo cp ../configs/hostapd.conf /etc/hostapd/hostapd.conf
echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' | sudo tee /etc/default/hostapd

# DHCPCD
sudo bash -c "cat ../configs/dhcpcd.conf.append >> /etc/dhcpcd.conf"

# DNSMASQ
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig || true
sudo cp ../configs/dnsmasq.conf /etc/dnsmasq.conf

# Enable IP forwarding
sudo cp ../configs/sysctl.conf.append /etc/sysctl.d/99-ipforward.conf
sudo sysctl -p /etc/sysctl.d/99-ipforward.conf

# Setup iptables NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables-save > ../scripts/iptables.rules
echo "iptables-restore < $(pwd)/iptables.rules" | sudo tee -a /etc/rc.local

# Start services
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl restart hostapd
sudo systemctl restart dnsmasq

echo "[+] Setup complete! Hotspot 'MITM_AP' is live!"
