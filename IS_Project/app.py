# app.py - UPDATED TWO-LAYER IPS SERVER
# - Two-layer detection (protocol + flow)
# - WHOIS context
# - Simulation mode + Start/Stop dataset replay
# - Falls back to live sniffing if no dataset present (requires admin & npcap)
# Place this file inside IS_Project/.

from flask import Flask, render_template, jsonify, request
import joblib
import pandas as pd
import numpy as np
import time
import threading
import sys
import os
import random

# Scapy is used for live sniffing only (optional on Windows)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
except Exception:
    sniff = None
    IP = TCP = UDP = ICMP = None
    wrpcap = None

from collections import defaultdict
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
import warnings
warnings.filterwarnings("ignore")

# ------------------------------
# CONFIG & GLOBAL STATE
# ------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")
DATASET_PATH = os.path.join(BASE_DIR, "CICIDS2017_sample.csv")  # optional dataset

FLOW_TIMEOUT = 5  # seconds
ACTIVE_FLOWS = defaultdict(list)
LOCK = threading.Lock()
ATTACKS_LOG = []                # dashboard log (most recent last)
TOTAL_FLOW_COUNT = {'value': 0}
BLOCKLIST = set()
MALICIOUS_PCAP_LOG = os.path.join(BASE_DIR, 'malicious_packets.pcap')
MAX_LOG_ENTRIES = 500

# Simulation/replay control
SIM_THREAD = None
SIM_RUNNING = False

# ------------------------------
# LOAD MODELS
# ------------------------------
try:
    SCALER = joblib.load(os.path.join(MODEL_DIR, "ids_scaler.joblib"))
    STK = joblib.load(os.path.join(MODEL_DIR, "ids_stacking_model.joblib"))
    DT = joblib.load(os.path.join(MODEL_DIR, "dt_model.joblib"))
    RF = joblib.load(os.path.join(MODEL_DIR, "rf_model.joblib"))
    ET = joblib.load(os.path.join(MODEL_DIR, "et_model.joblib"))
    XG = joblib.load(os.path.join(MODEL_DIR, "xg_model.joblib"))
    LABEL_ENCODER = joblib.load(os.path.join(MODEL_DIR, "label_encoder.joblib"))
    FLOW_FEATURE_NAMES = joblib.load(os.path.join(MODEL_DIR, "flow_features.joblib"))
    PROTOCOL_MODEL = joblib.load(os.path.join(MODEL_DIR, "protocol_anomaly_model.joblib"))
    PROTOCOL_FEATURE_NAMES = joblib.load(os.path.join(MODEL_DIR, "protocol_feature_names.joblib"))
    print("✅ All Two-Layer IPS components loaded successfully.")
except FileNotFoundError as e:
    print(f"❌ Missing model file: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ MODEL LOAD ERROR: {e}")
    sys.exit(1)

# ------------------------------
# WHOIS HELPER
# ------------------------------
def get_ip_context(ip_address):
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_whois()
        return {
            'org': results.get('asn_description', 'N/A'),
            'country': results.get('asn_country_code', 'N/A')
        }
    except IPDefinedError:
        return {'org': 'Private/Reserved IP', 'country': 'N/A'}
    except Exception:
        return {'org': 'Lookup Failed', 'country': 'N/A'}

# ------------------------------
# LAYER 1: Protocol Anomaly
# ------------------------------
def check_protocol_anomaly_packet(packet):
    if IP not in packet:
        return False, None
    features = {col: 0 for col in PROTOCOL_FEATURE_NAMES}
    try:
        features['ip_len'] = getattr(packet[IP], 'len', 0)
        features['ip_hdr_len'] = getattr(packet[IP], 'ihl', 0)
        features['ip_flags'] = int(getattr(packet[IP], 'flags', 0))
        features['ip_ttl'] = getattr(packet[IP], 'ttl', 0)
        features['protocol'] = getattr(packet[IP], 'proto', 0)

        if TCP in packet:
            features['tcp_src_port'] = packet[TCP].sport
            features['tcp_dst_port'] = packet[TCP].dport
            features['tcp_flags'] = int(packet[TCP].flags)
            features['payload_len'] = len(packet[TCP].payload)
        elif UDP in packet:
            features['payload_len'] = len(packet[UDP].payload)
        elif ICMP in packet:
            features['payload_len'] = len(packet[ICMP].payload)

        df = pd.DataFrame([features], columns=PROTOCOL_FEATURE_NAMES).fillna(0)
        pred = PROTOCOL_MODEL.predict(df)
        if int(pred[0]) == 1:
            return True, packet[IP].src
    except Exception:
        pass
    return False, None

def check_protocol_anomaly_row(row):
    features = {col: 0 for col in PROTOCOL_FEATURE_NAMES}
    try:
        if 'Protocol' in row:
            features['protocol'] = row['Protocol']
        if 'Flow Duration' in row:
            features['ip_len'] = row.get('Flow Duration', 0)
        if 'Total Length of Fwd Packets' in row:
            features['payload_len'] = row.get('Total Length of Fwd Packets', 0)
        df = pd.DataFrame([features], columns=PROTOCOL_FEATURE_NAMES).fillna(0)
        pred = PROTOCOL_MODEL.predict(df)
        return int(pred[0]) == 1
    except Exception:
        return False

# ------------------------------
# LAYER 2: Flow Anomaly
# ------------------------------
def predict_flow_anomaly_from_features(feature_dict, packets_for_logging=None):
    global ATTACKS_LOG, BLOCKLIST
    try:
        df = pd.DataFrame([feature_dict], columns=FLOW_FEATURE_NAMES)
        df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)
        scaled = SCALER.transform(df)

        preds = np.concatenate([
            DT.predict(scaled).reshape(-1, 1),
            ET.predict(scaled).reshape(-1, 1),
            RF.predict(scaled).reshape(-1, 1),
            XG.predict(scaled).reshape(-1, 1),
        ], axis=1)

        label_int = STK.predict(preds)[0]
        label = LABEL_ENCODER.inverse_transform([label_int])[0]

        if label != 'BENIGN':
            attacker = None
            dest = None
            sport = '-'
            dport = '-'
            if packets_for_logging and len(packets_for_logging) > 0:
                first = packets_for_logging[0]
                attacker = first[IP].src if IP in first else None
                dest = first[IP].dst if IP in first else None
                sport = getattr(first, 'sport', sport)
                dport = getattr(first, 'dport', dport)
                try:
                    if wrpcap:
                        wrpcap(MALICIOUS_PCAP_LOG, first, append=True)
                except Exception:
                    pass
            if attacker is None:
                attacker = feature_dict.get('Source IP', 'Unknown')
            if dest is None:
                dest = feature_dict.get('Destination IP', 'Unknown')

            BLOCKLIST.add(attacker)
            ctx = get_ip_context(attacker)
            log_entry = {
                'timestamp': time.strftime("%H:%M:%S"),
                'attack': label,
                'source': f"{attacker}:{sport}",
                'destination': f"{dest}:{dport}",
                'context': f"{ctx['org']} ({ctx['country']})"
            }
            with LOCK:
                ATTACKS_LOG.append(log_entry)
                if len(ATTACKS_LOG) > MAX_LOG_ENTRIES:
                    del ATTACKS_LOG[0:len(ATTACKS_LOG)-MAX_LOG_ENTRIES]
            print(f"🚨 ALERT: {label} from {attacker} -> {dest} [{ctx['org']}, {ctx['country']}]")
    except Exception as e:
        print("⚠️ Flow prediction error:", e)

# ------------------------------
# FLOW FEATURE EXTRACTION
# ------------------------------
def calculate_iat_stats(times):
    if len(times) < 2:
        return 0,0,0,0,0
    diffs = np.diff(times) * 1_000_000
    return (times[-1]-times[0])*1_000_000, np.mean(diffs), np.std(diffs), np.max(diffs), np.min(diffs)

def extract_flow_features(flow_key, flow_packets):
    features = {name: 0.0 for name in FLOW_FEATURE_NAMES}
    fwd = [p for p in flow_packets if getattr(p, 'direction','fwd')=='fwd']
    bwd = [p for p in flow_packets if getattr(p,'direction','')=='bwd']

    fwd_lens = np.array([p[IP].len for p in fwd]) if fwd else np.array([0])
    bwd_lens = np.array([p[IP].len for p in bwd]) if bwd else np.array([0])
    times = np.array([p.ts for p in flow_packets])

    features['Flow Duration'] = (flow_packets[-1].ts - flow_packets[0].ts)*1_000_000
    features['Total Fwd Packets'] = len(fwd)
    features['Total Backward Packets'] = len(bwd)
    features['Total Length of Fwd Packets'] = np.sum(fwd_lens)
    if len(fwd) > 0:
        features['Fwd Packet Length Mean'] = np.mean(fwd_lens)
    _, features['Flow IAT Mean'], features['Flow IAT Std'], features['Flow IAT Max'], features['Flow IAT Min'] = calculate_iat_stats(times)
    return features

# ------------------------------
# PACKET HANDLER
# ------------------------------
def packet_handler(packet):
    try:
        if IP not in packet:
            return
        src = packet[IP].src
        if src in BLOCKLIST:
            return
        TOTAL_FLOW_COUNT['value'] += 1

        is_anom, src_anom = check_protocol_anomaly_packet(packet)
        if is_anom:
            if src_anom and src_anom not in BLOCKLIST:
                BLOCKLIST.add(src_anom)
            ctx = get_ip_context(src_anom if src_anom else src)
            with LOCK:
                ATTACKS_LOG.append({
                    'timestamp': time.strftime("%H:%M:%S"),
                    'attack': 'PROTOCOL_ANOMALY',
                    'source': src_anom if src_anom else src,
                    'destination': packet[IP].dst if IP in packet else 'N/A',
                    'context': f"{ctx['org']} ({ctx['country']})"
                })
            return

        if TCP in packet or UDP in packet:
            proto = 6 if TCP in packet else 17
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            key_components = sorted([(src, sport),(packet[IP].dst,dport)])
            flow_key = (key_components[0][0], key_components[0][1], key_components[1][0], key_components[1][1], proto)
            direction = 'fwd' if (src,sport)==key_components[0] else 'bwd'
            packet.ts = time.time()
            packet.direction = direction
            with LOCK:
                ACTIVE_FLOWS[flow_key].append(packet)
    except Exception:
        pass

# ------------------------------
# FLOW MANAGER
# ------------------------------
def flow_manager():
    while True:
        time.sleep(FLOW_TIMEOUT/2)
        now = time.time()
        with LOCK:
            keys_to_process = [k for k,p in ACTIVE_FLOWS.items() if p and now - p[-1].ts > FLOW_TIMEOUT]
            for key in keys_to_process:
                packets = ACTIVE_FLOWS.pop(key)
                if len(packets) > 1:
                    features = extract_flow_features(key, packets)
                    predict_flow_anomaly_from_features(features, packets)

# ------------------------------
# DATASET REPLAY LOOP
# ------------------------------
def replay_dataset_loop(sleep_per_row=0.2):
    global SIM_RUNNING, TOTAL_FLOW_COUNT
    if not os.path.exists(DATASET_PATH):
        print("⚠️ Dataset not found:", DATASET_PATH)
        return
    try:
        df = pd.read_csv(DATASET_PATH).fillna(0)
    except Exception as e:
        print("⚠️ Failed to load dataset:", e)
        return
    print(f"📂 Replay dataset loaded: {len(df)} rows.")
    idx = 0
    n = len(df)
    while SIM_RUNNING:
        row = df.iloc[idx % n]
        idx += 1
        TOTAL_FLOW_COUNT['value'] += 1

        try:
            if check_protocol_anomaly_row(row):
                src = row.get('Source IP','Unknown')
                dst = row.get('Destination IP','Unknown')
                ctx = get_ip_context(src)
                with LOCK:
                    ATTACKS_LOG.append({
                        'timestamp': time.strftime("%H:%M:%S"),
                        'attack': 'PROTOCOL_ANOMALY',
                        'source': f"{src}:{row.get('Source Port','-')}",
                        'destination': f"{dst}:{row.get('Destination Port','-')}",
                        'context': f"{ctx['org']} ({ctx['country']})"
                    })
                time.sleep(sleep_per_row)
                continue
        except Exception:
            pass

        try:
            feat = {}
            for f in FLOW_FEATURE_NAMES:
                feat[f] = row.get(f, 0)
            feat['Source IP'] = row.get('Source IP', row.get('Src IP','Unknown'))
            feat['Destination IP'] = row.get('Destination IP', row.get('Dst IP','Unknown'))
            feat['Source Port'] = row.get('Source Port', row.get('Src Port','-'))
            feat['Destination Port'] = row.get('Destination Port', row.get('Dst Port','-'))
            predict_flow_anomaly_from_features(feat, packets_for_logging=None)
        except Exception:
            pass
        time.sleep(sleep_per_row)

# ------------------------------
# FLASK APP & ENDPOINTS
# ------------------------------
app = Flask(__name__, template_folder=os.path.join(BASE_DIR,'templates'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def data():
    with LOCK:
        return jsonify({
            'attacks': list(reversed(ATTACKS_LOG)),
            'active_flows': len(ACTIVE_FLOWS),
            'total_flows': TOTAL_FLOW_COUNT['value'],
            'blocked_ips': len(BLOCKLIST),
            'sim_running': SIM_RUNNING
        })

@app.route('/start', methods=['POST'])
def start_simulation():
    global SIM_THREAD, SIM_RUNNING
    if SIM_RUNNING:
        return jsonify({'status':'already_running'})
    SIM_RUNNING = True
    SIM_THREAD = threading.Thread(target=replay_dataset_loop, daemon=True)
    SIM_THREAD.start()
    return jsonify({'status':'replay_started'})

@app.route('/stop', methods=['POST'])
def stop_simulation():
    global SIM_RUNNING
    if SIM_RUNNING:
        SIM_RUNNING = False
        return jsonify({'status':'stopped'})
    return jsonify({'status':'not_running'})

# ------------------------------
# LIVE SNIFFER WRAPPER
# ------------------------------
def sniffer_loop_wrapper():
    if not sniff:
        print("⚠️ Scapy sniff not available.")
        return
    print("🛰️ Starting live sniffing...")
    try:
        sniff(prn=packet_handler, store=False, iface=None, filter="ip")
    except Exception as e:
        print("⚠️ Sniffing error:", e)

# ------------------------------
# STARTUP BEHAVIOR
# ------------------------------
if __name__ == '__main__':
    # Always start flow manager
    threading.Thread(target=flow_manager, daemon=True).start()
    # Start live sniffing if scapy available
    if sniff:
        threading.Thread(target=sniffer_loop_wrapper, daemon=True).start()
        print("📡 Live sniffing started (real-time packets).")
    else:
        print("⚠️ Live sniffing unavailable (requires Scapy & admin/Npcap).")
    print("🚀 IPS server running. Open http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
