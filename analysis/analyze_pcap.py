#!/usr/bin/env python3
"""
analyze_pcap.py

Advanced PCAP analyzer with detailed protocol breakdown, statistics, and summary tables.

Usage:
    python analyze_pcap.py <pcap_file> [--csv output.csv]

"""

import sys
import argparse
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
from prettytable import PrettyTable
import pandas as pd
from collections import Counter, defaultdict

def analyze_pcap(pcap_path, csv_out=None):
    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets)} packets from {pcap_path}\n")

    # Data containers
    protocol_counts = Counter()
    src_ip_counts = Counter()
    dst_ip_counts = Counter()
    tcp_flags_counts = Counter()
    total_bytes = 0

    detailed_rows = []

    for i, pkt in enumerate(packets, 1):
        # Timestamp
        timestamp = pkt.time

        # Packet length
        length = len(pkt)
        total_bytes += length

        # Defaults
        src_ip = dst_ip = src_port = dst_port = protocol = "-"
        tcp_flags = ""

        if ARP in pkt:
            protocol = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst

        elif IP in pkt:
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if TCP in pkt:
                protocol = "TCP"
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = tcp_layer.flags

                # TCP flags parsing
                flag_str = []
                if flags & 0x02:
                    flag_str.append("SYN")
                if flags & 0x10:
                    flag_str.append("ACK")
                if flags & 0x01:
                    flag_str.append("FIN")
                if flags & 0x04:
                    flag_str.append("RST")
                tcp_flags = ",".join(flag_str)
                tcp_flags_counts.update(flag_str)

            elif UDP in pkt:
                protocol = "UDP"
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            elif ICMP in pkt:
                protocol = "ICMP"

            else:
                protocol = ip_layer.proto

        else:
            protocol = pkt.name

        # Update counters
        protocol_counts[protocol] += 1
        src_ip_counts[src_ip] += 1
        dst_ip_counts[dst_ip] += 1

        # Append detailed row for CSV/logging
        detailed_rows.append({
            "No.": i,
            "Timestamp": timestamp,
            "Src IP": src_ip,
            "Dst IP": dst_ip,
            "Src Port": src_port,
            "Dst Port": dst_port,
            "Protocol": protocol,
            "TCP Flags": tcp_flags,
            "Length": length,
        })

    # Summary tables
    print_summary(protocol_counts, tcp_flags_counts, src_ip_counts, dst_ip_counts, total_bytes, len(packets))

    # Save CSV if requested
    if csv_out:
        save_to_csv(detailed_rows, csv_out)


def print_summary(protocol_counts, tcp_flags_counts, src_ip_counts, dst_ip_counts, total_bytes, total_packets):
    print("="*60)
    print("Packet Capture Analysis Summary")
    print("="*60)

    # Protocol breakdown table
    pt_protocols = PrettyTable()
    pt_protocols.field_names = ["Protocol", "Packets", "Percentage"]
    for proto, count in protocol_counts.most_common():
        pct = (count / total_packets) * 100
        pt_protocols.add_row([proto, count, f"{pct:.2f}%"])
    print("\nProtocol Distribution:")
    print(pt_protocols)

    # TCP Flags table
    if tcp_flags_counts:
        pt_flags = PrettyTable()
        pt_flags.field_names = ["TCP Flag", "Count"]
        for flag, count in tcp_flags_counts.most_common():
            pt_flags.add_row([flag, count])
        print("\nTCP Flags Counts:")
        print(pt_flags)

    # Top 10 Source IPs
    pt_src = PrettyTable()
    pt_src.field_names = ["Top Source IPs", "Packets"]
    for ip, count in src_ip_counts.most_common(10):
        pt_src.add_row([ip, count])
    print("\nTop 10 Source IP Addresses:")
    print(pt_src)

    # Top 10 Destination IPs
    pt_dst = PrettyTable()
    pt_dst.field_names = ["Top Destination IPs", "Packets"]
    for ip, count in dst_ip_counts.most_common(10):
        pt_dst.add_row([ip, count])
    print("\nTop 10 Destination IP Addresses:")
    print(pt_dst)

    print(f"\nTotal Packets: {total_packets}")
    print(f"Total Bytes Captured: {total_bytes} bytes")
    print("="*60)


def save_to_csv(rows, filename):
    print(f"\n[+] Saving detailed packet log to {filename}")
    df = pd.DataFrame(rows)
    df.to_csv(filename, index=False)
    print("[+] CSV export completed.\n")


def main():
    parser = argparse.ArgumentParser(description="Advanced PCAP Analyzer")
    parser.add_argument("pcapfile", help="Path to the PCAP file to analyze")
    parser.add_argument("--csv", help="Output CSV file to save detailed packet info", default=None)
    args = parser.parse_args()

    analyze_pcap(args.pcapfile, args.csv)


if __name__ == "__main__":
    main()
