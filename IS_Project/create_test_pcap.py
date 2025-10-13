# create_test_pcap.py
# This script GENERATES a PCAP file with demo packets. It does not send them.
# Run this script ONCE to create the test file.

from scapy.all import IP, TCP, Raw, wrpcap

print("🔧 Creating test PCAP file with malicious packets...")

# Define the packets
target_ip = "127.0.0.1"
target_port = 80

clean_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
clean_packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=clean_payload)

sqli_payload = b"POST /login HTTP/1.1\r\nHost: test.com\r\n\r\nuser=' OR 1=1;--&pass=123"
sqli_packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=sqli_payload)

xss_payload = b"GET /search?q=<script>alert('attacked')</script> HTTP/1.1\r\nHost: anothersite.com\r\n"
xss_packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load=xss_payload)

# Create a list of packets
demo_packets = [clean_packet, sqli_packet, xss_packet]

# Write the packets to a PCAP file
output_filename = "test_packets.pcap"
wrpcap(output_filename, demo_packets)

print(f"✅ Successfully created '{output_filename}' with {len(demo_packets)} packets.")