# app.py - ADVANCED TWO-LAYER REAL-TIME IPS v2
# Adds a log of all processed packets to the dashboard.

from flask import Flask, render_template, jsonify
import joblib
import pandas as pd
import numpy as np
import time
import threading
import os
from collections import defaultdict
import warnings

# Scapy is required
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
except ImportError:
    print("❌ Scapy is not installed. Please run: pip install scapy")
    exit()

warnings.filterwarnings("ignore")

# ------------------------------
# CONFIG & GLOBAL STATE
# ------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

MALICIOUS_SIGNATURES = { "SQL Injection": b"' OR 1=1", "XSS Attack": b"<script>", "Directory Traversal": b"../../" }

FLOW_TIMEOUT = 10
ACTIVE_FLOWS = defaultdict(list)
LOCK = threading.Lock()
ALERTS_LOG = []
PROCESSED_PACKETS_LOG = [] # <-- NEW: Log for all packets
TOTAL_PACKET_COUNT = {'value': 0}
CONTENT_THREATS_FOUND = {'value': 0}
BEHAVIOR_THREATS_FOUND = {'value': 0}
BLOCKLIST = set()
MAX_LOG_ENTRIES = 500
MAX_PACKET_LOG = 100 # <-- NEW: Limit for the processed packet log

# ------------------------------
# LOAD MODELS (For Layer 2)
# ------------------------------
try:
    SCALER = joblib.load(os.path.join(MODEL_DIR, "ids_scaler.joblib"))
    STK = joblib.load(os.path.join(MODEL_DIR, "ids_stacking_model.joblib"))
    DT = joblib.load(os.path.join(MODEL_DIR, "dt_model.joblib"))
    RF = joblib.load(os.path.join(MODEL_DIR, "rf_model.joblib"))
    ET = joblib.load(os.path.join(MODEL_DIR, "et_model.joblib"))
    XG = joblib.load(os.path.join(MODEL_DIR, "xg_model.joblib"))
    LABEL_ENCODER = joblib.load(os.path.join(MODEL_DIR, "label_encoder.joblib"))
    FEATURE_NAMES = joblib.load(os.path.join(MODEL_DIR, "flow_features.joblib"))
    print("✅ All ML Model components (Layer 2) loaded successfully.")
    MODELS_LOADED = True
except Exception as e:
    print(f"❌ Could not load ML models: {e}")
    MODELS_LOADED = False

# -----------------------------------
# LAYER 1: CONTENT INSPECTION & CLEANING
# -----------------------------------
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

# ------------------------------
# LAYER 2: FLOW FEATURE EXTRACTION
# ------------------------------
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

# ------------------------------
# LIVE PACKET HANDLER
# ------------------------------
def live_packet_handler(packet):
    global TOTAL_PACKET_COUNT, CONTENT_THREATS_FOUND, ALERTS_LOG, PROCESSED_PACKETS_LOG
    if not packet.haslayer(IP): return

    TOTAL_PACKET_COUNT['value'] += 1

    # --- NEW: Log every packet that is processed ---
    protocol = packet.getlayer(IP).get_field('proto').i2s.get(packet.proto, f'#{packet.proto}')
    packet_details = {
        'timestamp': time.strftime("%H:%M:%S"),
        'source': packet[IP].src,
        'destination': packet[IP].dst,
        'protocol': protocol.upper(),
        'length': len(packet)
    }
    with LOCK:
        PROCESSED_PACKETS_LOG.append(packet_details)

    # --- Layer 1: Content Inspection ---
    cleaned_packet, attack_type, original_payload = inspect_and_clean_packet(packet.copy())
    if attack_type:
        CONTENT_THREATS_FOUND['value'] += 1
        log_entry = { 'timestamp': time.strftime("%H:%M:%S"), 'layer': 1, 'alert_type': "Content Threat Cleaned", 'details': f"Type: {attack_type}", 'source_ip': packet[IP].src, 'dest_ip': packet[IP].dst, 'content': original_payload }
        with LOCK: ALERTS_LOG.append(log_entry)

    # --- Layer 2: Behavioral Analysis ---
    if MODELS_LOADED:
        try:
            src_ip, dst_ip, proto, sport, dport = cleaned_packet[IP].src, cleaned_packet[IP].dst, cleaned_packet[IP].proto, cleaned_packet.sport, cleaned_packet.dport
            key_components = sorted([(src_ip, sport), (dst_ip, dport)])
            flow_key = (key_components[0][0], key_components[0][1], key_components[1][0], key_components[1][1], proto)
            cleaned_packet.direction = 'fwd' if (src_ip, sport) == key_components[0] else 'bwd'
            with LOCK: ACTIVE_FLOWS[flow_key].append(cleaned_packet)
        except Exception: pass

# ------------------------------
# FLOW MANAGER (For Layer 2)
# ------------------------------
def flow_manager():
    global BEHAVIOR_THREATS_FOUND, ALERTS_LOG
    while True:
        time.sleep(FLOW_TIMEOUT / 2)
        with LOCK:
            keys_to_process = [k for k, p in ACTIVE_FLOWS.items() if time.time() - p[-1].time > FLOW_TIMEOUT]
            for key in keys_to_process:
                flow_packets = ACTIVE_FLOWS.pop(key)
                if len(flow_packets) < 2 or not MODELS_LOADED: continue
                features = extract_flow_features(flow_packets)
                if not features: continue
                try:
                    df = pd.DataFrame([features], columns=FEATURE_NAMES).fillna(0)
                    scaled_features = SCALER.transform(df)
                    base_model_preds = np.concatenate([
                        DT.predict(scaled_features).reshape(-1, 1), ET.predict(scaled_features).reshape(-1, 1),
                        RF.predict(scaled_features).reshape(-1, 1), XG.predict(scaled_features).reshape(-1, 1),
                    ], axis=1)
                    prediction = STK.predict(base_model_preds)
                    label = LABEL_ENCODER.inverse_transform(prediction)[0]
                    if label != 'BENIGN':
                        BEHAVIOR_THREATS_FOUND['value'] += 1
                        attacker_ip = flow_packets[0][IP].src
                        BLOCKLIST.add(attacker_ip)
                        log_entry = { 'timestamp': time.strftime("%H:%M:%S"), 'layer': 2, 'alert_type': "Behavioral Threat Blocked", 'details': f"Type: {label}", 'source_ip': attacker_ip, 'dest_ip': flow_packets[0][IP].dst, 'content': f"{len(flow_packets)} packets in flow" }
                        ALERTS_LOG.append(log_entry)
                except Exception as e:
                    print(f"⚠️ ML Prediction Error: {e}")

# ------------------------------
# FLASK APP & ENDPOINTS
# ------------------------------
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

@app.route('/')
def index(): return render_template('index.html')

@app.route('/data')
def data():
    with LOCK:
        if len(ALERTS_LOG) > MAX_LOG_ENTRIES: del ALERTS_LOG[0:len(ALERTS_LOG) - MAX_LOG_ENTRIES]
        if len(PROCESSED_PACKETS_LOG) > MAX_PACKET_LOG: del PROCESSED_PACKETS_LOG[0:len(PROCESSED_PACKETS_LOG) - MAX_PACKET_LOG]
        return jsonify({
            'alerts': list(reversed(ALERTS_LOG)),
            'processed_packets': list(reversed(PROCESSED_PACKETS_LOG)), # <-- NEW: Send processed packets
            'total_packets': TOTAL_PACKET_COUNT['value'],
            'content_threats': CONTENT_THREATS_FOUND['value'],
            'behavior_threats': BEHAVIOR_THREATS_FOUND['value'],
            'blocked_ips': len(BLOCKLIST)
        })

# ------------------------------
# STARTUP
# ------------------------------
if __name__ == '__main__':
    if MODELS_LOADED: threading.Thread(target=flow_manager, daemon=True).start()
    print("🚀 Starting Two-Layer IPS...")
    print("🛰️ Layer 1 (Content Inspection) is ACTIVE.")
    print("🧠 Layer 2 (Behavior Analysis) is ACTIVE." if MODELS_LOADED else "⚠️ Layer 2 (Behavior Analysis) is INACTIVE.")
    is_windows = os.name == 'nt'
    if is_windows:
        threading.Thread(target=lambda: sniff(prn=live_packet_handler, store=False, filter="ip"), daemon=True).start()
        app.run(host='0.0.0.0', port=5000)
    else:
        print(" L- On Linux/macOS, run with 'sudo python app.py'")
        threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5000), daemon=True).start()
        try:
            sniff(prn=live_packet_handler, store=False, filter="ip")
        except PermissionError:
            print("\n❌ PermissionError: Please run with 'sudo'.")
        except Exception as e:
            print(f"\n❌ Sniffing error: {e}")