# PRODIGY_CS_05

from scapy.all import *

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
            print(f"Payload: {packet[TCP].payload}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
            print(f"Payload: {packet[UDP].payload}")

# Capture packets on the network interface 'eth0'
sniff(iface='eth0', prn=packet_handler)
