# # app.py - FINAL UPDATED TWO-LAYER IPS SERVER (Windows Compatible + WHOIS + Improved Path Handling)

# from flask import Flask, render_template, jsonify
# import joblib
# import pandas as pd
# import numpy as np
# import time
# import threading
# import sys
# import os

# # Scapy imports
# from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
# from collections import defaultdict

# # WHOIS lookup
# from ipwhois import IPWhois
# from ipwhois.exceptions import IPDefinedError

# import warnings
# warnings.filterwarnings("ignore")

# # ------------------------------
# # GLOBAL STATE
# # ------------------------------
# FLOW_TIMEOUT = 5  # seconds
# ACTIVE_FLOWS = defaultdict(list)
# LOCK = threading.Lock()
# ATTACKS_LOG = []  # for Flask dashboard
# TOTAL_FLOW_COUNT = {'value': 0}
# BLOCKLIST = set()
# MALICIOUS_PCAP_LOG = 'malicious_packets.pcap'
# MAX_LOG_ENTRIES = 500  # Limit attack history size

# # ------------------------------
# # PATH SETUP (Windows-safe)
# # ------------------------------
# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# MODEL_DIR = os.path.join(BASE_DIR, "models")

# # ------------------------------
# # LOAD MODELS
# # ------------------------------
# try:
#     SCALER = joblib.load(os.path.join(MODEL_DIR, "ids_scaler.joblib"))
#     STK = joblib.load(os.path.join(MODEL_DIR, "ids_stacking_model.joblib"))
#     DT = joblib.load(os.path.join(MODEL_DIR, "dt_model.joblib"))
#     RF = joblib.load(os.path.join(MODEL_DIR, "rf_model.joblib"))
#     ET = joblib.load(os.path.join(MODEL_DIR, "et_model.joblib"))
#     XG = joblib.load(os.path.join(MODEL_DIR, "xg_model.joblib"))
#     LABEL_ENCODER = joblib.load(os.path.join(MODEL_DIR, "label_encoder.joblib"))
#     FLOW_FEATURE_NAMES = joblib.load(os.path.join(MODEL_DIR, "flow_features.joblib"))

#     PROTOCOL_MODEL = joblib.load(os.path.join(MODEL_DIR, "protocol_anomaly_model.joblib"))
#     PROTOCOL_FEATURE_NAMES = joblib.load(os.path.join(MODEL_DIR, "protocol_feature_names.joblib"))

#     print("✅ All Two-Layer IPS components loaded successfully.")
# except FileNotFoundError as e:
#     print(f"❌ FATAL ERROR: Missing model file - {e}")
#     sys.exit(1)
# except Exception as e:
#     print(f"❌ MODEL LOAD ERROR: {e}")
#     sys.exit(1)

# # ------------------------------
# # WHOIS LOOKUP
# # ------------------------------
# def get_ip_context(ip_address):
#     """Return WHOIS info for an IP (organization and country)."""
#     try:
#         obj = IPWhois(ip_address)
#         results = obj.lookup_whois()
#         return {
#             'org': results.get('asn_description', 'N/A'),
#             'country': results.get('asn_country_code', 'N/A')
#         }
#     except IPDefinedError:
#         return {'org': 'Private/Reserved IP', 'country': 'N/A'}
#     except Exception:
#         return {'org': 'Lookup Failed', 'country': 'N/A'}

# # ------------------------------
# # LAYER 1: Protocol Anomaly Detection
# # ------------------------------
# def check_protocol_anomaly(packet):
#     if IP not in packet:
#         return False, None

#     features = {col: 0 for col in PROTOCOL_FEATURE_NAMES}
#     features['ip_len'] = packet[IP].len
#     features['ip_hdr_len'] = packet[IP].ihl
#     features['ip_flags'] = int(packet[IP].flags)
#     features['ip_ttl'] = packet[IP].ttl
#     features['protocol'] = packet[IP].proto

#     if TCP in packet:
#         features['tcp_src_port'] = packet[TCP].sport
#         features['tcp_dst_port'] = packet[TCP].dport
#         features['tcp_flags'] = int(packet[TCP].flags)
#         features['payload_len'] = len(packet[TCP].payload)
#     elif UDP in packet:
#         features['payload_len'] = len(packet[UDP].payload)
#     elif ICMP in packet:
#         features['payload_len'] = len(packet[ICMP].payload)

#     try:
#         df = pd.DataFrame([features], columns=PROTOCOL_FEATURE_NAMES)
#         df.fillna(0, inplace=True)
#         prediction = PROTOCOL_MODEL.predict(df)
#         if prediction[0] == 1:
#             return True, packet[IP].src
#     except Exception:
#         pass
#     return False, None

# # ------------------------------
# # LAYER 2: Flow Anomaly Detection
# # ------------------------------
# def calculate_iat_stats(times):
#     if len(times) < 2:
#         return 0, 0, 0, 0, 0
#     diffs = np.diff(times) * 1_000_000
#     return (times[-1] - times[0]) * 1_000_000, np.mean(diffs), np.std(diffs), np.max(diffs), np.min(diffs)

# def extract_flow_features(flow_key, flow_packets):
#     features = {n: 0.0 for n in FLOW_FEATURE_NAMES}
#     fwd = [p for p in flow_packets if p.direction == 'fwd']
#     bwd = [p for p in flow_packets if p.direction == 'bwd']

#     fwd_lens = np.array([p[IP].len for p in fwd]) if fwd else np.array([0])
#     bwd_lens = np.array([p[IP].len for p in bwd]) if bwd else np.array([0])
#     times = np.array([p.ts for p in flow_packets])

#     features['Flow Duration'] = (flow_packets[-1].ts - flow_packets[0].ts) * 1_000_000
#     features['Total Fwd Packets'] = len(fwd)
#     features['Total Length of Fwd Packets'] = np.sum(fwd_lens)
#     if len(fwd) > 0:
#         features['Fwd Packet Length Mean'] = np.mean(fwd_lens)
#     _, features['Flow IAT Mean'], features['Flow IAT Std'], features['Flow IAT Max'], features['Flow IAT Min'] = calculate_iat_stats(times)

#     return features

# def predict_flow_anomaly(flow_key, feature_dict, packets):
#     global ATTACKS_LOG, BLOCKLIST

#     df = pd.DataFrame([feature_dict], columns=FLOW_FEATURE_NAMES)
#     df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)
#     scaled = SCALER.transform(df)

#     preds = np.concatenate([
#         DT.predict(scaled).reshape(-1, 1),
#         ET.predict(scaled).reshape(-1, 1),
#         RF.predict(scaled).reshape(-1, 1),
#         XG.predict(scaled).reshape(-1, 1)
#     ], axis=1)

#     label_int = STK.predict(preds)[0]
#     label = LABEL_ENCODER.inverse_transform([label_int])[0]

#     if label != 'BENIGN':
#         first = packets[0]
#         attacker = first[IP].src
#         context = get_ip_context(attacker)
#         wrpcap(MALICIOUS_PCAP_LOG, first, append=True)

#         if attacker not in BLOCKLIST:
#             print(f"🛑 Blocking {attacker} for attack type: {label}")
#             BLOCKLIST.add(attacker)

#         log = {
#             'timestamp': time.strftime("%H:%M:%S"),
#             'attack': label,
#             'source': f"{attacker}:{getattr(first, 'sport', 'N/A')}",
#             'destination': f"{first[IP].dst}:{getattr(first, 'dport', 'N/A')}",
#             'context': f"{context['org']} ({context['country']})"
#         }
#         with LOCK:
#             ATTACKS_LOG.append(log)
#             if len(ATTACKS_LOG) > MAX_LOG_ENTRIES:
#                 ATTACKS_LOG = ATTACKS_LOG[-MAX_LOG_ENTRIES:]
#         print(f"🚨 ALERT: {label} from {attacker} [{context['org']}, {context['country']}]")

# # ------------------------------
# # PACKET HANDLER
# # ------------------------------
# def packet_handler(packet):
#     try:
#         if IP not in packet:
#             return
#         if packet[IP].src in BLOCKLIST:
#             return

#         TOTAL_FLOW_COUNT['value'] += 1
#         src_ip = packet[IP].src

#         is_anomaly, src_anom = check_protocol_anomaly(packet)
#         if is_anomaly:
#             if src_anom not in BLOCKLIST:
#                 print(f"🛑 Blocking malformed source: {src_anom}")
#                 BLOCKLIST.add(src_anom)
#             ctx = get_ip_context(src_anom)
#             with LOCK:
#                 ATTACKS_LOG.append({
#                     'timestamp': time.strftime("%H:%M:%S"),
#                     'attack': 'PROTOCOL_ANOMALY',
#                     'source': src_anom,
#                     'destination': 'N/A',
#                     'context': f"{ctx['org']} ({ctx['country']})"
#                 })
#             return

#         if TCP in packet or UDP in packet:
#             proto = 6 if TCP in packet else 17
#             sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
#             dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
#             key = sorted([(src_ip, sport), (packet[IP].dst, dport)])
#             flow_key = (key[0][0], key[0][1], key[1][0], key[1][1], proto)
#             direction = 'fwd' if (src_ip, sport) == key[0] else 'bwd'

#             packet.ts = time.time()
#             packet.direction = direction
#             with LOCK:
#                 ACTIVE_FLOWS[flow_key].append(packet)
#     except Exception:
#         pass

# # ------------------------------
# # FLOW MANAGER
# # ------------------------------
# def flow_manager():
#     while True:
#         time.sleep(FLOW_TIMEOUT / 2)
#         now = time.time()
#         with LOCK:
#             keys_to_process = [k for k, p in ACTIVE_FLOWS.items() if p and now - p[-1].ts > FLOW_TIMEOUT]
#             for key in keys_to_process:
#                 packets = ACTIVE_FLOWS.pop(key)
#                 if len(packets) > 1:
#                     feats = extract_flow_features(key, packets)
#                     predict_flow_anomaly(key, feats, packets)

# # ------------------------------
# # SNIFFER
# # ------------------------------
# def sniffer_loop():
#     try:
#         sniff(prn=packet_handler, store=False, iface=None, filter="ip")
#     except Exception as e:
#         print(f"⚠️ Sniffing Error: {e}")
#         print("Run as Administrator or Sudo if permissions denied.")

# # ------------------------------
# # FLASK DASHBOARD
# # ------------------------------
# if __name__ == '__main__':
#     sniffer = threading.Thread(target=sniffer_loop, daemon=True)
#     manager = threading.Thread(target=flow_manager, daemon=True)
#     print("🚀 Starting Two-Layer IPS (Windows Compatible)...")
#     sniffer.start()
#     manager.start()

#     app = Flask(__name__)

#     @app.route('/')
#     def index():
#         return render_template('index.html')

#     @app.route('/data')
#     def data():
#         with LOCK:
#             return jsonify({
#                 'attacks': list(reversed(ATTACKS_LOG)),
#                 'active_flows': len(ACTIVE_FLOWS),
#                 'total_flows': TOTAL_FLOW_COUNT['value'],
#                 'blocked_ips': len(BLOCKLIST)
#             })

#     app.run(debug=False, host='0.0.0.0', port=5000)




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
DATASET_PATH = os.path.join(BASE_DIR, "CICIDS2017_sample.csv")  # dataset replay file (optional)

FLOW_TIMEOUT = 5  # seconds (flow inactivity to consider finished)
ACTIVE_FLOWS = defaultdict(list)
LOCK = threading.Lock()
ATTACKS_LOG = []                # dashboard log (most recent last)
TOTAL_FLOW_COUNT = {'value': 0}
BLOCKLIST = set()
MALICIOUS_PCAP_LOG = os.path.join(BASE_DIR, 'malicious_packets.pcap')
MAX_LOG_ENTRIES = 500           # cap log size to avoid memory bloat

# Simulation/replay control
SIM_THREAD = None
SIM_RUNNING = False

# Mode choice: if dataset present we'll use replay mode by default
USE_REPLAY = os.path.exists(DATASET_PATH)

# ------------------------------
# LOAD MODELS (all saved joblibs expected in models/)
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
    print(f"❌ FATAL ERROR: Missing model file - {e}")
    print("Make sure the 'models' folder contains the required .joblib files.")
    sys.exit(1)
except Exception as e:
    print(f"❌ MODEL LOAD ERROR: {e}")
    sys.exit(1)

# ------------------------------
# WHOIS HELPER
# ------------------------------
def get_ip_context(ip_address):
    """Return simple WHOIS context: org and country (best-effort)."""
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
# LAYER 1: Protocol Anomaly (per-packet or per-row)
# ------------------------------
def check_protocol_anomaly_packet(packet):
    """Run protocol anomaly model on a Scapy packet. Returns (is_anomaly, src_ip)."""
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

        df = pd.DataFrame([features], columns=PROTOCOL_FEATURE_NAMES)
        df.fillna(0, inplace=True)
        pred = PROTOCOL_MODEL.predict(df)
        if int(pred[0]) == 1:
            return True, packet[IP].src
    except Exception:
        pass
    return False, None

def check_protocol_anomaly_row(row):
    """Run protocol anomaly model on a dataset row (replay mode)."""
    try:
        features = {col: 0 for col in PROTOCOL_FEATURE_NAMES}
        # map a few common fields if present
        if 'Protocol' in row:
            features['protocol'] = row['Protocol']
        if 'Flow Duration' in row:
            features['ip_len'] = row.get('Flow Duration', 0)
        # payload length fallback
        if 'Total Length of Fwd Packets' in row:
            features['payload_len'] = row.get('Total Length of Fwd Packets', 0)

        df = pd.DataFrame([features], columns=PROTOCOL_FEATURE_NAMES).fillna(0)
        pred = PROTOCOL_MODEL.predict(df)
        return int(pred[0]) == 1
    except Exception:
        return False

# ------------------------------
# LAYER 2: Flow Anomaly (ML stacking)
# ------------------------------
def predict_flow_anomaly_from_features(feature_dict, packets_for_logging=None):
    """feature_dict is a dict of FLOW_FEATURE_NAMES -> value (single flow).
       packets_for_logging optional (list of scapy packets) for pcap/logging."""
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
            # choose attacker IP from packets if available, else from feature_dict
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
                # save pcap if wrpcap available
                try:
                    if wrpcap:
                        wrpcap(MALICIOUS_PCAP_LOG, first, append=True)
                except Exception:
                    pass
            # fallback to feature fields
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
                    # keep newest MAX_LOG_ENTRIES
                    del ATTACKS_LOG[0:len(ATTACKS_LOG)-MAX_LOG_ENTRIES]
            print(f"🚨 ALERT: {label} from {attacker} -> {dest} [{ctx['org']}, {ctx['country']}]")
    except Exception as e:
        print("⚠️ Flow prediction error:", e)

# ------------------------------
# FLOW FEATURE EXTRACTION (from scapy packets)
# ------------------------------
def calculate_iat_stats(times):
    if len(times) < 2:
        return 0, 0, 0, 0, 0
    diffs = np.diff(times) * 1_000_000
    return (times[-1] - times[0]) * 1_000_000, np.mean(diffs), np.std(diffs), np.max(diffs), np.min(diffs)

def extract_flow_features(flow_key, flow_packets):
    """Return feature dict (keys in FLOW_FEATURE_NAMES) from scapy packets in a flow."""
    features = {name: 0.0 for name in FLOW_FEATURE_NAMES}
    fwd = [p for p in flow_packets if getattr(p, 'direction', 'fwd') == 'fwd']
    bwd = [p for p in flow_packets if getattr(p, 'direction', 'fwd') == 'bwd' or getattr(p, 'direction', '') == 'bwd']

    fwd_lens = np.array([p[IP].len for p in fwd]) if fwd else np.array([0])
    bwd_lens = np.array([p[IP].len for p in bwd]) if bwd else np.array([0])
    times = np.array([p.ts for p in flow_packets])

    features['Flow Duration'] = (flow_packets[-1].ts - flow_packets[0].ts) * 1_000_000
    features['Total Fwd Packets'] = len(fwd)
    features['Total Backward Packets'] = len(bwd)
    features['Total Length of Fwd Packets'] = np.sum(fwd_lens)
    if len(fwd) > 0:
        features['Fwd Packet Length Mean'] = np.mean(fwd_lens)
    _, features['Flow IAT Mean'], features['Flow IAT Std'], features['Flow IAT Max'], features['Flow IAT Min'] = calculate_iat_stats(times)
    return features

# ------------------------------
# PACKET HANDLER (for live sniffing)
# ------------------------------
def packet_handler(packet):
    try:
        if IP not in packet:
            return
        src = packet[IP].src
        # skip blocked IPs early
        if src in BLOCKLIST:
            return

        TOTAL_FLOW_COUNT['value'] += 1

        # Layer 1 check
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

        # build flows (TCP/UDP only)
        if TCP in packet or UDP in packet:
            proto = 6 if TCP in packet else 17
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
            key_components = sorted([(src, sport), (packet[IP].dst, dport)])
            flow_key = (key_components[0][0], key_components[0][1], key_components[1][0], key_components[1][1], proto)
            direction = 'fwd' if (src, sport) == key_components[0] else 'bwd'
            packet.ts = time.time()
            packet.direction = direction
            with LOCK:
                ACTIVE_FLOWS[flow_key].append(packet)
    except Exception:
        pass

# ------------------------------
# FLOW MANAGER (periodically process flows)
# ------------------------------
def flow_manager():
    while True:
        time.sleep(FLOW_TIMEOUT / 2)
        now = time.time()
        with LOCK:
            keys_to_process = [k for k, p in ACTIVE_FLOWS.items() if p and now - p[-1].ts > FLOW_TIMEOUT]
            for key in keys_to_process:
                packets = ACTIVE_FLOWS.pop(key)
                if len(packets) > 1:
                    features = extract_flow_features(key, packets)
                    predict_flow_anomaly_from_features(features, packets)

# ------------------------------
# DATASET REPLAY (simulation mode)
# ------------------------------
def replay_dataset_loop(sleep_per_row=0.2):
    """Replay rows from CICIDS2017_sample.csv while SIM_RUNNING True."""
    global SIM_RUNNING, ATTACKS_LOG, TOTAL_FLOW_COUNT
    if not os.path.exists(DATASET_PATH):
        print("⚠️ Dataset for replay not found:", DATASET_PATH)
        return

    try:
        df = pd.read_csv(DATASET_PATH).fillna(0)
    except Exception as e:
        print("⚠️ Failed to load dataset for replay:", e)
        return

    print(f"📂 Replay dataset loaded: {len(df)} rows. Starting replay...")
    idx = 0
    n = len(df)
    while SIM_RUNNING:
        row = df.iloc[idx % n]
        idx += 1
        TOTAL_FLOW_COUNT['value'] += 1

        # Layer 1 (dataset row)
        try:
            if check_protocol_anomaly_row(row):
                src = row.get('Source IP', 'Unknown')
                dst = row.get('Destination IP', 'Unknown')
                ctx = get_ip_context(src)
                with LOCK:
                    ATTACKS_LOG.append({
                        'timestamp': time.strftime("%H:%M:%S"),
                        'attack': 'PROTOCOL_ANOMALY',
                        'source': f"{src}:{row.get('Source Port','-')}",
                        'destination': f"{dst}:{row.get('Destination Port','-')}",
                        'context': f"{ctx['org']} ({ctx['country']})"
                    })
                # small pause and next row
                time.sleep(sleep_per_row)
                continue
        except Exception:
            pass

        # Layer 2 (flow prediction using available numeric columns)
        try:
            # build a feature_dict with available flow feature names from CSV
            feat = {}
            for f in FLOW_FEATURE_NAMES:
                # CSV columns may not match; attempt a few common name variants
                if f in row:
                    feat[f] = row[f]
                else:
                    # accept simpler keys: try uppercase/no punctuation matches
                    key_alt = f
                    if key_alt in row:
                        feat[f] = row[key_alt]
                    else:
                        feat[f] = row.get(f, 0)
            # add IPs/ports for logging fallback
            feat['Source IP'] = row.get('Source IP', row.get('Src IP', 'Unknown'))
            feat['Destination IP'] = row.get('Destination IP', row.get('Dst IP', 'Unknown'))
            feat['Source Port'] = row.get('Source Port', row.get('Src Port', '-'))
            feat['Destination Port'] = row.get('Destination Port', row.get('Dst Port', '-'))

            predict_flow_anomaly_from_features(feat, packets_for_logging=None)
        except Exception as e:
            # non-fatal
            pass

        # small sleep to avoid spinning too fast — makes dashboard readable
        time.sleep(sleep_per_row)

# ------------------------------
# SIMULATION CONTROL & ENDPOINTS
# ------------------------------
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def data():
    with LOCK:
        return jsonify({
            'attacks': list(reversed(ATTACKS_LOG)),  # newest first for UI
            'active_flows': len(ACTIVE_FLOWS),
            'total_flows': TOTAL_FLOW_COUNT['value'],
            'blocked_ips': len(BLOCKLIST),
            'sim_running': SIM_RUNNING,
            'mode': 'replay' if USE_REPLAY else 'sniff'
        })

@app.route('/simulate', methods=['POST'])
def simulate():
    """Inject one fake simulated alert for demo (used by dashboard button)."""
    fake_types = ['PortScan', 'DoS', 'Botnet', 'WebAttack', 'BruteForce', 'Infiltration']
    atk = random.choice(fake_types)
    fake_src = f"192.168.1.{random.randint(2,254)}"
    fake_dst = f"192.168.1.{random.randint(2,254)}"
    fake_sport = random.randint(1024, 65535)
    fake_dport = random.choice([80, 443, 22, 3389, 8080])
    ctx = get_ip_context(fake_src)
    log_entry = {
        'timestamp': time.strftime("%H:%M:%S"),
        'attack': atk,
        'source': f"{fake_src}:{fake_sport}",
        'destination': f"{fake_dst}:{fake_dport}",
        'context': f"{ctx['org']} ({ctx['country']})"
    }
    with LOCK:
        ATTACKS_LOG.append(log_entry)
        if len(ATTACKS_LOG) > MAX_LOG_ENTRIES:
            del ATTACKS_LOG[0:len(ATTACKS_LOG)-MAX_LOG_ENTRIES]
    return jsonify({'status': 'ok', 'log': log_entry})

@app.route('/start', methods=['POST', 'GET'])
def start_simulation():
    """Start dataset replay (if available) or enable sniffing threads if not."""
    global SIM_THREAD, SIM_RUNNING, USE_REPLAY
    if SIM_RUNNING:
        return jsonify({'status': 'already_running'})

    if USE_REPLAY:
        SIM_RUNNING = True
        SIM_THREAD = threading.Thread(target=replay_dataset_loop, daemon=True)
        SIM_THREAD.start()
        return jsonify({'status': 'replay_started'})
    else:
        # start live sniffing + flow manager threads
        try:
            # start flow manager
            fm = threading.Thread(target=flow_manager, daemon=True)
            fm.start()
            # start sniffer if scapy available
            if sniff:
                sn = threading.Thread(target=sniffer_loop_wrapper, daemon=True)
                sn.start()
                return jsonify({'status': 'sniffing_started'})
            else:
                return jsonify({'status': 'no_sniffer_available'})
        except Exception as e:
            return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/stop', methods=['POST', 'GET'])
def stop_simulation():
    """Stop dataset replay. Note: stopping live sniffing may require killing the process."""
    global SIM_RUNNING
    if SIM_RUNNING:
        SIM_RUNNING = False
        return jsonify({'status': 'stopped'})
    else:
        return jsonify({'status': 'not_running'})

# Helper wrapper to start scapy sniffing (keeps the original sniffer loop name)
def sniffer_loop_wrapper():
    if not sniff:
        print("⚠️ Scapy sniff not available on this environment.")
        return
    print("🛰️ Starting live sniffing (requires admin/Npcap).")
    try:
        sniff(prn=packet_handler, store=False, iface=None, filter="ip")
    except Exception as e:
        print("⚠️ Sniffing error:", e)

# ------------------------------
# STARTUP BEHAVIOR
# ------------------------------
if __name__ == '__main__':
    # If using replay by default, start it automatically (but keep /stop available)
    if USE_REPLAY:
        SIM_RUNNING = True
        SIM_THREAD = threading.Thread(target=replay_dataset_loop, daemon=True)
        SIM_THREAD.start()
        print("📡 Dataset replay started automatically (found CICIDS2017_sample.csv).")
    else:
        # start flow manager and sniffer (if scapy available)
        print("📡 No dataset found — starting live sniffing (if supported).")
        fm = threading.Thread(target=flow_manager, daemon=True)
        fm.start()
        if sniff:
            sn = threading.Thread(target=sniffer_loop_wrapper, daemon=True)
            sn.start()
        else:
            print("⚠️ Live sniffing unavailable (Scapy not installed or platform unsupported).")

    print("🚀 IPS server running. Open http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
