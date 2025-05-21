#!/bin/bash
echo "[+] Restoring network to default..."

# Remove hostapd, dnsmasq, NAT
sudo systemctl stop hostapd
sudo systemctl stop dnsmasq
sudo iptables -t nat -F

# Restore original dnsmasq.conf
sudo mv /etc/dnsmasq.conf.orig /etc/dnsmasq.conf || true

# Remove static IP from dhcpcd.conf
sudo sed -i '/interface wlan0/,+2d' /etc/dhcpcd.conf

# Remove sysctl file
sudo rm -f /etc/sysctl.d/99-ipforward.conf
sudo sysctl -p

echo "[+] Reboot your device to finalize cleanup."
