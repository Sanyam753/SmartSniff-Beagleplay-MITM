

````markdown
🔥 BeaglePlay MITM Gateway for IoT Device Surveillance

This project demonstrates a Man-In-The-Middle (MITM) attack setup using the BeaglePlay as a Wi-Fi gateway to intercept and analyze data from IoT devices (like smartwatches, smart bulbs, etc.). The captured data is analyzed and stored using Kali Linux as the attacker's machine. This is an educational and research-focused setup to understand IoT vulnerabilities, not for unethical use.

---

⚙️ Project Overview

- Gateway: [BeaglePlay](https://beagleboard.org/play) — acts as a fake Wi-Fi access point.
- Victim: Any smart IoT device (e.g., smartwatch, phone, Ubuntu system) connecting to the BeaglePlay Wi-Fi.
- Attacker: Kali Linux system — captures and inspects network packets using tools like Wireshark, `tcpdump`, or `ettercap`.


![MITM](https://github.com/user-attachments/assets/09d35d74-8b38-482b-9ede-602b9229d043)



🛠️ Step 1: Flashing Debian on BeaglePlay

1. Download Debian Image
   Get the latest [BeaglePlay Debian Image](https://beagleboard.org/latest-images).

2. Flash the image to SD Card
   - Use [`balenaEtcher`](https://www.balena.io/etcher/) or `dd` command:
     ```bash
     sudo dd if=debian-image.img of=/dev/sdX bs=4M status=progress
     ```

3. Insert the SD card into BeaglePlay and boot up.

4. Connect to BeaglePlay via:
   - USB Ethernet gadget (default: `192.168.7.2`)
   - Ethernet cable
   - Serial over USB (e.g., using `screen /dev/ttyACM0 115200`)

5. Login
   ```bash
   username: debian
   password: temppwd
````



## 📶 Step 2: Configure BeaglePlay as Wi-Fi Access Point

### 🔌 2.1 Install Required Packages

```bash
sudo apt update
sudo apt install hostapd dnsmasq iptables
sudo systemctl stop hostapd
sudo systemctl stop dnsmasq
```



### 📁 2.2 Create Hostapd Config File

```bash
sudo nano /etc/hostapd/hostapd.conf
```

Paste the following:

```ini
interface=wlan0
driver=nl80211
ssid=MITM_AP
hw_mode=g
channel=6
auth_algs=1
wmm_enabled=0
wpa=2
wpa_passphrase=mitmpassword
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

Edit `/etc/default/hostapd`:

```bash
sudo nano /etc/default/hostapd
```

Add:

```ini
DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

---

### 🌐 2.3 Assign Static IP to `wlan0`

Edit `dhcpcd.conf`:

```bash
sudo nano /etc/dhcpcd.conf
```

Append:

```ini
interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
```

---

### 📦 2.4 Configure DHCP and DNS with `dnsmasq`

```bash
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
sudo nano /etc/dnsmasq.conf
```

Paste:

```ini
interface=wlan0
dhcp-range=192.168.4.10,192.168.4.50,255.255.255.0,24h
```

---

### 🔁 2.5 Enable IP Forwarding

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo nano /etc/sysctl.conf
```

Uncomment:

```ini
net.ipv4.ip_forward=1
```

Apply it:

```bash
sudo sysctl -p
```

---

###  2.6 Setup NAT with iptables

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables-save | sudo tee /etc/iptables.ipv4.nat
```

Make it persistent:

```bash
sudo nano /etc/rc.local
```

Add before `exit 0`:

```bash
iptables-restore < /etc/iptables.ipv4.nat
```

---

###  2.7 Start the Access Point

```bash
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl restart hostapd
sudo systemctl restart dnsmasq
```

> BeaglePlay is now hosting a Wi-Fi hotspot: **SSID: MITM\_AP | Password: mitmpassword**

---

##  Step 3: Victim Setup (Smartwatch / Smart Device / Ubuntu)

1. Boot any smart device or Linux system with Wi-Fi capability.
2. Connect to the fake AP:
   **SSID**: `MITM_AP`
   **Password**: `mitmpassword`
3. Once connected, the device will use the BeaglePlay as its gateway.

---

##  Step 4: Attacker Machine (Kali Linux)

The Kali system must be connected to BeaglePlay's Ethernet port (or USB Ethernet), to monitor or collect traffic.

###  4.1 Monitor Network Traffic

Use `tcpdump`:

```bash
sudo tcpdump -i eth0 -w mitm_traffic.pcap
```

Or open Wireshark:

```bash
sudo wireshark
```

Capture on interface `eth0` or `usb0`.

---

### 🔍 4.2 Analyze Data

Filter DNS, HTTP, or MQTT traffic from smart devices:

* HTTP: `http`
* DNS: `udp.port == 53`
* MQTT: `tcp.port == 1883`
* TLS: `tls`

---

##  Step 5: Collect & Store Data

* Export `.pcap` from Wireshark.
* Parse using Python + Scapy:

```python
from scapy.all import *

packets = rdpcap('mitm_traffic.pcap')
for pkt in packets:
    if pkt.haslayer(IP):
        print(pkt[IP].src, '→', pkt[IP].dst)
```

---

## 🧾 Repository Structure

```bash
beagleplay-mitm-gateway/
├── configs/
│   ├── hostapd.conf
│   ├── dnsmasq.conf
│   ├── dhcpcd.conf
│   └── iptables.ipv4.nat
├── scripts/
│   ├── setup_ap.sh         # Auto setup script for AP
│   └── sniff_packets.sh    # tcpdump/wireshark automation
├── analysis/
│   └── analyze_pcap.py     # Python script to read packets
├── README.md
└── LICENSE
```

---

## 🚨 Disclaimer

This project is strictly for **educational purposes** and ethical cybersecurity research. Do **not** use it for malicious or unauthorized network monitoring. Misuse may lead to legal consequences.


## ✍️ Authors

* Sanyam Sankhala
* BeaglePlay-based IoT researcher


## 📬 Contact

Feel free to reach out at:
📧 [sanyamsankhala13@gmail.com](mailto:sanyamsankhala13@gmail.com)
📍 VIT Chennai


