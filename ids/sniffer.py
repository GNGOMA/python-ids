from scapy.all import sniff, rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        print(f"{src} → {dst} | proto={proto} | len={length}")

def start_live(iface="eth0", count=50):
    print(f"[*] Sniffing on {iface}...")
    sniff(iface=iface, prn=packet_callback, count=count, store=False)

def start_pcap(filepath):
    print(f"[*] Reading {filepath}...")
    packets = rdpcap(filepath)
    for pkt in packets:
        packet_callback(pkt)
