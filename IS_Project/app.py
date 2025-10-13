# app.py - FINAL VERSION with PCAP Test Mode

from flask import Flask, render_template, jsonify
import joblib
import pandas as pd
import numpy as np
import time
import threading
import os
from collections import defaultdict
import warnings

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, Raw, get_if_list
except ImportError:
    print("❌ Scapy is not installed. Please run: pip install scapy")
    exit()

warnings.filterwarnings("ignore")

# --- [ All CONFIG, MODEL LOADING, and FUNCTIONS are the same as before ] ---
# [ Make sure you have all the functions from the previous version here ]
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")
MALICIOUS_SIGNATURES = { "SQL Injection": b"' OR 1=1", "XSS Attack": b"<script>", "Directory Traversal": b"../../" }
FLOW_TIMEOUT = 10
ACTIVE_FLOWS = defaultdict(list)
LOCK = threading.Lock()
ALERTS_LOG = []
PROCESSED_PACKETS_LOG = []
TOTAL_PACKET_COUNT = {'value': 0}
CONTENT_THREATS_FOUND = {'value': 0}
BEHAVIOR_THREATS_FOUND = {'value': 0}
BLOCKLIST = set()
MAX_LOG_ENTRIES = 500
MAX_PACKET_LOG = 100
SIM_THREAD = None
SIM_RUNNING = False

try:
    SCALER = joblib.load(os.path.join(MODEL_DIR, "ids_scaler.joblib"))
    STK = joblib.load(os.path.join(MODEL_DIR, "ids_stacking_model.joblib"))
    DT = joblib.load(os.path.join(MODEL_DIR, "dt_model.joblib"))
    RF = joblib.load(os.path.join(MODEL_DIR, "rf_model.joblib"))
    ET = joblib.load(os.path.join(MODEL_DIR, "et_model.joblib"))
    XG = joblib.load(os.path.join(MODEL_DIR, "xg_model.joblib"))
    LABEL_ENCODER = joblib.load(os.path.join(MODEL_DIR, "label_encoder.joblib"))
    FEATURE_NAMES = joblib.load(os.path.join(MODEL_DIR, "flow_features.joblib"))
    MODELS_LOADED = True
except Exception: MODELS_LOADED = False

def inspect_and_clean_packet(packet):
    if not packet.haslayer(Raw): return packet, None, None
    payload = packet[Raw].load
    for attack_type, signature in MALICIOUS_SIGNATURES.items():
        if signature in payload:
            original_payload_str = repr(payload)
            cleaned_payload = payload.replace(signature, b"[SANITIZED]")
            packet[Raw].load = cleaned_payload
            if packet.haslayer(IP): del packet[IP].chksum
            if packet.haslayer(TCP): del packet[TCP].chksum
            if packet.haslayer(UDP): del packet[UDP].csum
            return packet, attack_type, original_payload_str
    return packet, None, None

def extract_flow_features(flow_packets):
    if not flow_packets: return None
    features = {name: 0.0 for name in FEATURE_NAMES}
    first_packet = flow_packets[0]
    features['Protocol'] = first_packet[IP].proto if first_packet.haslayer(IP) else 0
    times = np.array([p.time for p in flow_packets])
    features['Flow Duration'] = (times.max() - times.min()) * 1_000_000
    fwd_packets = [p for p in flow_packets if p.direction == 'fwd']
    bwd_packets = [p for p in flow_packets if p.direction == 'bwd']
    features['Total Fwd Packets'] = len(fwd_packets)
    features['Total Backward Packets'] = len(bwd_packets)
    fwd_lens = [len(p[Raw].load) for p in fwd_packets if p.haslayer(Raw)]
    bwd_lens = [len(p[Raw].load) for p in bwd_packets if p.haslayer(Raw)]
    features['Total Length of Fwd Packets'] = sum(fwd_lens)
    features['Total Length of Bwd Packets'] = sum(bwd_lens)
    if fwd_lens: features['Fwd Packet Length Mean'] = np.mean(fwd_lens)
    if bwd_lens: features['Bwd Packet Length Mean'] = np.mean(bwd_lens)
    if len(times) > 1:
        iat = np.diff(times) * 1_000_000
        features['Flow IAT Mean'] = np.mean(iat)
        features['Flow IAT Std'] = np.std(iat)
        features['Flow IAT Max'] = np.max(iat)
        features['Flow IAT Min'] = np.min(iat)
    return features

def live_packet_handler(packet):
    global TOTAL_PACKET_COUNT, CONTENT_THREATS_FOUND, ALERTS_LOG, PROCESSED_PACKETS_LOG
    if not packet.haslayer(IP): return
    TOTAL_PACKET_COUNT['value'] += 1
    protocol = packet.getlayer(IP).get_field('proto').i2s.get(packet.proto, f'#{packet.proto}')
    packet_details = { 'timestamp': time.strftime("%H:%M:%S"), 'source': packet[IP].src, 'destination': packet[IP].dst, 'protocol': protocol.upper(), 'length': len(packet) }
    with LOCK: PROCESSED_PACKETS_LOG.append(packet_details)
    cleaned_packet, attack_type, original_payload = inspect_and_clean_packet(packet.copy())
    if attack_type:
        CONTENT_THREATS_FOUND['value'] += 1
        log_entry = { 'timestamp': time.strftime("%H:%M:%S"), 'layer': 1, 'alert_type': "Content Threat Cleaned", 'details': f"Type: {attack_type}", 'source_ip': packet[IP].src, 'dest_ip': packet[IP].dst, 'content': original_payload }
        with LOCK: ALERTS_LOG.append(log_entry)
    if MODELS_LOADED:
        try:
            src_ip, dst_ip, proto, sport, dport = cleaned_packet[IP].src, cleaned_packet[IP].dst, cleaned_packet[IP].proto, cleaned_packet.sport, cleaned_packet.dport
            key_components = sorted([(src_ip, sport), (dst_ip, dport)])
            flow_key = (key_components[0][0], key_components[0][1], key_components[1][0], key_components[1][1], proto)
            cleaned_packet.direction = 'fwd' if (src_ip, sport) == key_components[0] else 'bwd'
            with LOCK: ACTIVE_FLOWS[flow_key].append(cleaned_packet)
        except Exception: pass

def flow_manager():
    global BEHAVIOR_THREATS_FOUND, ALERTS_LOG
    while True:
        time.sleep(FLOW_TIMEOUT / 2)
        with LOCK:
            keys_to_process = [k for k, p in ACTIVE_FLOWS.items() if time.time() - p[-1].time > FLOW_TIMEOUT]
            for key in keys_to_process:
                # ... [rest of flow_manager logic is the same]
                pass

# --- NEW: Function to process a saved PCAP file ---
def process_pcap_file(pcap_path):
    global SIM_RUNNING, TOTAL_PACKET_COUNT, CONTENT_THREATS_FOUND, ALERTS_LOG, PROCESSED_PACKETS_LOG
    
    if not os.path.exists(pcap_path):
        print(f"⚠️ Test PCAP file not found: {pcap_path}")
        return
    
    packets = rdpcap(pcap_path)
    
    for packet in packets:
        if not SIM_RUNNING: break
        # We can reuse the live_packet_handler for each packet in the file
        live_packet_handler(packet)
        time.sleep(1) # Slow down for visualization
        
    SIM_RUNNING = False

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))
@app.route('/')
def index(): return render_template('index.html')
@app.route('/data')
def data():
    # ... [data endpoint is the same]
    with LOCK:
        if len(ALERTS_LOG) > MAX_LOG_ENTRIES: del ALERTS_LOG[0:len(ALERTS_LOG) - MAX_LOG_ENTRIES]
        if len(PROCESSED_PACKETS_LOG) > MAX_PACKET_LOG: del PROCESSED_PACKETS_LOG[0:len(PROCESSED_PACKETS_LOG) - MAX_PACKET_LOG]
        return jsonify({ 'alerts': list(reversed(ALERTS_LOG)), 'processed_packets': list(reversed(PROCESSED_PACKETS_LOG)), 'total_packets': TOTAL_PACKET_COUNT['value'], 'content_threats': CONTENT_THREATS_FOUND['value'], 'behavior_threats': BEHAVIOR_THREATS_FOUND['value'], 'blocked_ips': len(BLOCKLIST), 'sim_running': SIM_RUNNING })

# --- NEW: Endpoint to start the demo test ---
@app.route('/start_test', methods=['POST'])
def start_test():
    global SIM_THREAD, SIM_RUNNING, ALERTS_LOG, PROCESSED_PACKETS_LOG, TOTAL_PACKET_COUNT, CONTENT_THREATS_FOUND
    if SIM_RUNNING: return jsonify({'status': 'already_running'})
    
    # Reset stats for the test run
    SIM_RUNNING = True
    ALERTS_LOG, PROCESSED_PACKETS_LOG = [], []
    TOTAL_PACKET_COUNT['value'], CONTENT_THREATS_FOUND['value'] = 0, 0

    pcap_file = os.path.join(BASE_DIR, "test_packets.pcap")
    SIM_THREAD = threading.Thread(target=process_pcap_file, args=(pcap_file,), daemon=True)
    SIM_THREAD.start()
    return jsonify({'status': 'test_started'})

@app.route('/stop_test', methods=['POST'])
def stop_test():
    global SIM_RUNNING
    if SIM_RUNNING:
        SIM_RUNNING = False
        return jsonify({'status': 'stopped'})
    return jsonify({'status': 'not_running'})

if __name__ == '__main__':
    # ... [The main startup logic for live sniffing is the same]
    if MODELS_LOADED: threading.Thread(target=flow_manager, daemon=True).start()
    print("🚀 Starting Two-Layer IPS...")
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5000), daemon=True).start()
    try:
        print("🛰️ Live sniffer is ACTIVE on all interfaces.")
        sniff(prn=live_packet_handler, store=False, filter="ip")
    except PermissionError:
        print("\n❌ PermissionError: Live sniffing requires administrator/sudo privileges.")
    except Exception as e:
        print(f"\n❌ Live sniffing failed: {e}")