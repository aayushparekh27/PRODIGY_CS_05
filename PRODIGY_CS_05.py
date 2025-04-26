from scapy.all import sniff, IP, TCP, Raw, wrpcap
from datetime import datetime
import os

# Output file for saving captured packets
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
pcap_file = f"captured_packets_{timestamp}.pcap"
log_file = f"packet_log_{timestamp}.txt"

# Store packets in memory to save later
captured_packets = []

def log_to_file(message):
    with open(log_file, "a") as f:
        f.write(message + "\n")

def packet_callback(packet):
    if IP in packet:
        proto = "TCP" if packet.haslayer(TCP) else "Other"
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        payload = ""
        if packet.haslayer(Raw):
            try:
                payload = str(packet[Raw].load[:50])
            except:
                payload = "[Unreadable Payload]"

        info = f"""
=== Packet Captured ===
Time       : {datetime.now().strftime("%H:%M:%S")}
Protocol   : {proto}
Source IP  : {src_ip}
Dest IP    : {dst_ip}
Payload    : {payload}
-------------------------
"""
        print(info)
        log_to_file(info)
        captured_packets.append(packet)

def main():
    print("=== Advanced Packet Sniffer ===")
    print("Capturing only TCP packets (CTRL+C to stop)...")
    try:
        sniff(filter="tcp", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped.")
        if captured_packets:
            wrpcap(pcap_file, captured_packets)
            print(f"\nPackets saved to: {pcap_file}")
        else:
            print("No packets captured.")
        print(f"Log saved to: {log_file}")

if __name__ == "__main__":
    main()
