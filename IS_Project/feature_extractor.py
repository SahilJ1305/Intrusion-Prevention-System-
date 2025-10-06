# feature_extractor.py
from scapy.all import rdpcap
import pandas as pd
import numpy as np
import os
import sys

def extract_features_from_pcap(pcap_file, label):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: {pcap_file} not found. Did you run tshark capture?")
        return []
        
    feature_list = []
    
    # These columns MUST match the training columns in protocol_model_trainer.py
    for packet in packets:
        if 'IP' in packet:
            features = {
                'ip_len': packet['IP'].len,
                'ip_hdr_len': packet['IP'].ihl,
                'ip_flags': int(packet['IP'].flags),
                'ip_ttl': packet['IP'].ttl,
                'protocol': packet['IP'].proto,
                'tcp_src_port': 0,
                'tcp_dst_port': 0,
                'tcp_flags': 0,
                'payload_len': 0,
                'label': label
            }

            if 'TCP' in packet:
                features['tcp_src_port'] = packet['TCP'].sport
                features['tcp_dst_port'] = packet['TCP'].dport
                features['tcp_flags'] = int(packet['TCP'].flags)
                features['payload_len'] = len(packet['TCP'].payload)
            elif 'UDP' in packet:
                features['payload_len'] = len(packet['UDP'].payload)
            elif 'ICMP' in packet:
                features['payload_len'] = len(packet['ICMP'].payload)

            feature_list.append(features)
            
    return feature_list

# --- Execution ---
print("Extracting features from PCAP files...")
# Process both normal (label 0) and anomalous (label 1) captures
normal_features = extract_features_from_pcap('normal_traffic.pcap', 0)
anomalous_features = extract_features_from_pcap('anomalous_traffic.pcap', 1)

# Combine and save to a CSV file
if normal_features or anomalous_features:
    full_dataset = pd.DataFrame(normal_features + anomalous_features)
    full_dataset.to_csv('protocol_anomaly_dataset.csv', index=False)
    print(f"Dataset created successfully: protocol_anomaly_dataset.csv (Total samples: {len(full_dataset)})")
else:
    print("No packets were extracted. Check PCAP files.")
    sys.exit(1)