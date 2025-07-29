# BeaglePlay MITM Gateway for IoT Device Surveillance

An educational, research‑focused lab setup that uses a BeaglePlay board as a rogue Wi‑Fi gateway to perform a Man‑In‑The‑Middle (MITM) interception of IoT device traffic. All captured packets are sent to a Kali Linux “attacker” machine for inspection, analysis, and storage.

**Disclaimer:** Only use this in a controlled environment with permission. Unauthorized interception is illegal.

## Project Overview

1. Gateway

   * Hardware: BeaglePlay
   * Role: Fake Wi‑Fi AP that all victim devices connect through

2. Victim Devices

   * Examples: smartwatches, smart bulbs, smartphones, Linux PCs

3. Attacker Machine

   * OS: Kali Linux
   * Tools: tcpdump, Wireshark, ettercap, Scapy

![MITM Setup](https://github.com/user-attachments/assets/09d35d74-8b38-482b-9ede-602b9229d043)

1. Flash Debian onto BeaglePlay

---

1. Download the latest Debian image
   – [BeaglePlay Debian images](https://beagleboard.org/latest-images)

2. Flash to SD card

   ```bash
   sudo dd if=debian-image.img of=/dev/sdX bs=4M status=progress
   ```

   (Or use balenaEtcher.)

3. Insert SD, power on, then connect via:

   * USB Ethernet gadget (default 192.168.7.2)
   * Ethernet cable
   * Serial console (`screen /dev/ttyACM0 115200`)

4. Login credentials:

   ```bash
   username: debian
   password: temppwd
   ```

5. Configure BeaglePlay as Wi‑Fi AP

---

### 2.1 Install packages

```bash
sudo apt update
sudo apt install hostapd dnsmasq iptables
sudo systemctl stop hostapd dnsmasq
```

### 2.2 hostapd setup

Create `/etc/hostapd/hostapd.conf`:

```ini
interface=wlan0
driver=nl80211
ssid=MITM_AP
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=mitmpassword
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

Point default config at it:

```bash
echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' \
  | sudo tee /etc/default/hostapd
```

### 2.3 Static IP for wlan0

Append to `/etc/dhcpcd.conf`:

```ini
interface wlan0
  static ip_address=192.168.4.1/24
  nohook wpa_supplicant
```

### 2.4 DHCP & DNS via dnsmasq

```bash
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
cat <<EOF | sudo tee /etc/dnsmasq.conf
interface=wlan0
dhcp-range=192.168.4.10,192.168.4.50,255.255.255.0,24h
EOF
```

### 2.5 Enable IP forwarding

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p
```

### 2.6 NAT with iptables

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables-save | sudo tee /etc/iptables.ipv4.nat
```

To restore at boot, add to `/etc/rc.local` before `exit 0`:

```bash
iptables-restore < /etc/iptables.ipv4.nat
```

### 2.7 Start services

```bash
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl restart hostapd dnsmasq
```

> The AP is now live as SSID MITM\_AP with password mitmpassword.

3. Victim Device Setup

---

1. Power on any Wi‑Fi‑enabled IoT or Linux device.

2. Connect to SSID MITM\_AP (password mitmpassword).

3. All traffic goes through BeaglePlay for interception.

4. Attacker Machine (Kali Linux)

---

Connect Kali to BeaglePlay via Ethernet or USB‑Ethernet.

### 4.1 Capture traffic

```bash
sudo tcpdump -i eth0 -w mitm_traffic.pcap
```

Or launch Wireshark, capturing on `eth0` or `usb0`.

### 4.2 Analyze traffic

Common filters:

* HTTP → `http`
* DNS → `udp.port == 53`
* MQTT → `tcp.port == 1883`
* TLS → `tls`

5. Data Analysis

---

1. Export the `.pcap` file.
2. Parse with Python + Scapy:

```python
from scapy.all import *
packets = rdpcap('mitm_traffic.pcap')
for pkt in packets:
    if pkt.haslayer(IP):
        print(pkt[IP].src, '→', pkt[IP].dst)
```

## Repository Structure

```
beagleplay-mitm-gateway/
├── configs/
│   ├── hostapd.conf
│   ├── dnsmasq.conf
│   ├── dhcpcd.conf
│   └── iptables.ipv4.nat
├── scripts/
│   ├── setup_ap.sh
│   └── sniff_packets.sh
├── analysis/
│   └── analyze_pcap.py
├── README.md
└── LICENSE
```

## Legal Disclaimer

This setup is strictly for **authorized educational** or **research** use. Any unauthorized interception of traffic is illegal and may carry severe penalties.

## Authors & Contact

* **Sanyam Sankhala** 
* 📧 [sanyamsankhala13@gmail.com](mailto:sanyamsankhala13@gmail.com)
* 📍 VIT Chennai
