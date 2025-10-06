# anomaly_generator.py
from scapy.all import send, IP, TCP, ICMP

# IMPORTANT: Replace with your local machine's IP address
target_ip = "10.75.224.129" 

print("Sending anomalous packets...")

# Anomaly 1: TCP packet with both SYN and FIN flags set (illegal combination)
packet1 = IP(dst=target_ip) / TCP(dport=80, flags="SF")
send(packet1, count=10, verbose=0)

# Anomaly 2: "Xmas" Scan Packet (FIN, PSH, URG flags set)
packet2 = IP(dst=target_ip) / TCP(dport=80, flags="FPU")
send(packet2, count=10, verbose=0)

# Anomaly 3: Land Attack (Source and Destination IP are the same)
packet3 = IP(src=target_ip, dst=target_ip) / TCP(dport=80)
send(packet3, count=5, verbose=0)

# Anomaly 4: ICMP Packet with an oversized payload (potential Ping of Death)
packet4 = IP(dst=target_ip) / ICMP() / ("X" * 1000)
send(packet4, count=5, verbose=0)

print("Finished sending anomalous packets.")