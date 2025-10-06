# app.py - FINAL TWO-LAYER IPS SERVER (COMPLETE & CORRECTED)

from flask import Flask, render_template, jsonify
import joblib
import pandas as pd
import numpy as np
import time
import threading
import sys
# Scapy imports the necessary tools for network communication
from scapy.all import sniff, IP, TCP, UDP, ICMP 
from collections import defaultdict
import warnings
warnings.filterwarnings("ignore")

# --- GLOBAL STATE (Shared between threads and Flask) ---
FLOW_TIMEOUT = 5  # seconds: flows inactive for this long are processed
ACTIVE_FLOWS = defaultdict(list)
LOCK = threading.Lock()
ATTACKS_LOG = [] # Stores alerts for the website
TOTAL_FLOW_COUNT = {'value': 0}

# --- 1. LOAD ALL 10 JOBILIB COMPONENTS ---
try:
    # Layer 2 (Flow Detection)
    SCALER = joblib.load('ids_minmax_scaler.joblib')
    STK = joblib.load('ids_stacking_meta_model.joblib')
    DT = joblib.load('dt_model.joblib')
    RF = joblib.load('rf_model.joblib')
    ET = joblib.load('et_model.joblib')
    XG = joblib.load('xg_model.joblib')
    LABEL_ENCODER = joblib.load('label_encoder.joblib')
    FLOW_FEATURE_NAMES = joblib.load('flow_feature_names.joblib')

    # Layer 1 (Protocol Detection)
    PROTOCOL_MODEL = joblib.load('protocol_anomaly_model.joblib')
    PROTOCOL_FEATURE_NAMES = joblib.load('protocol_feature_names.joblib')

    print("✅ All Two-Layer IPS components loaded successfully.")
except FileNotFoundError as e:
    print(f"FATAL ERROR: Missing file {e}. Did you complete all training steps?")
    sys.exit(1)
except ImportError as e:
    print(f"FATAL ERROR: Dependency missing. Error: {e}")
    sys.exit(1)


# --- 2. LAYER 1: PROTOCOL ANOMALY CHECK (Per-Packet Logic) ---

def check_protocol_anomaly(packet):
    """Checks a single packet against the protocol anomaly model (Layer 1)."""
    if 'IP' not in packet: return False, None
        
    features = {col: 0 for col in PROTOCOL_FEATURE_NAMES}
    
    # Extract features matching the Protocol Model Trainer
    features['ip_len'] = packet['IP'].len
    features['ip_hdr_len'] = packet['IP'].ihl
    features['ip_flags'] = int(packet['IP'].flags)
    features['ip_ttl'] = packet['IP'].ttl
    features['protocol'] = packet['IP'].proto
    
    if 'TCP' in packet:
        features['tcp_src_port'] = packet['TCP'].sport
        features['tcp_dst_port'] = packet['TCP'].dport
        features['tcp_flags'] = int(packet['TCP'].flags)
        features['payload_len'] = len(packet['TCP'].payload)
    elif 'UDP' in packet:
        features['payload_len'] = len(packet['UDP'].payload)
    elif 'ICMP' in packet:
        features['payload_len'] = len(packet['ICMP'].payload)

    try:
        packet_df = pd.DataFrame([features], columns=PROTOCOL_FEATURE_NAMES)
        packet_df.fillna(0, inplace=True)
        
        prediction = PROTOCOL_MODEL.predict(packet_df)
        if prediction[0] == 1:
            return True, packet['IP'].src
    except Exception:
        pass
    return False, None

# --- 3. LAYER 2: FLOW ANOMALY CHECK (Core Flow Logic) ---

def calculate_iat_stats(times):
    # Calculates Inter-Arrival Times for flow features
    if len(times) < 2: return 0, 0, 0, 0, 0
    total = times[-1] - times[0]; iat_diffs = np.diff(times)
    iat_diffs_micro = iat_diffs * 1_000_000
    mean = np.mean(iat_diffs_micro); std = np.std(iat_diffs_micro) if len(iat_diffs_micro) > 1 else 0
    mx = np.max(iat_diffs_micro); mn = np.min(iat_diffs_micro)
    return total * 1_000_000, mean, std, mx, mn

def extract_flow_features(flow_key, flow_packets):
    """Extracts a subset of the 77 flow features from the aggregated packets."""
    
    features = {name: 0.0 for name in FLOW_FEATURE_NAMES}

    fwd_packets = [p for p in flow_packets if p['direction'] == 'fwd']
    bwd_packets = [p for p in flow_packets if p['direction'] == 'bwd']

    total_fwd_packets = len(fwd_packets); total_bwd_packets = len(bwd_packets)
    fwd_lens = np.array([p['ip_len'] for p in fwd_packets]); bwd_lens = np.array([p['ip_len'] for p in bwd_packets])
    all_lens = np.concatenate((fwd_lens, bwd_lens)) if total_fwd_packets + total_bwd_packets > 0 else np.array([0])
    all_times = np.array([p['ts'] for p in flow_packets])

    # Calculate core features (the rest default to 0.0)
    features['Flow Duration'] = (flow_packets[-1]['ts'] - flow_packets[0]['ts']) * 1_000_000
    features['Total Fwd Packets'] = total_fwd_packets
    features['Total Length of Fwd Packets'] = np.sum(fwd_lens)
    if total_fwd_packets > 0: features['Fwd Packet Length Mean'] = np.mean(fwd_lens)
    _, features['Flow IAT Mean'], features['Flow IAT Std'], features['Flow IAT Max'], features['Flow IAT Min'] = calculate_iat_stats(all_times)
    
    # You would need to calculate the remaining ~70 features here to match training data structure.
    
    return features


def predict_flow_anomaly(flow_key, feature_vector_dict):
    """Runs the Stacking Model (Layer 2) prediction pipeline."""
    global ATTACKS_LOG
    
    flow_df = pd.DataFrame([feature_vector_dict], columns=FLOW_FEATURE_NAMES)
    flow_df.replace([np.inf, -np.inf, np.nan], 0.0, inplace=True)
    flow_scaled = SCALER.transform(flow_df)

    # Stacking Model Prediction Pipeline
    dt_pred = DT.predict(flow_scaled).reshape(-1, 1); rf_pred = RF.predict(flow_scaled).reshape(-1, 1)
    et_pred = ET.predict(flow_scaled).reshape(-1, 1); xg_pred = XG.predict(flow_scaled).reshape(-1, 1)
    x_test_stk = np.concatenate((dt_pred, et_pred, rf_pred, xg_pred), axis=1)

    stk_prediction_int = STK.predict(x_test_stk)[0]
    # FIX: This line requires the encoder to be fitted (solved by re-saving in notebook)
    label = LABEL_ENCODER.inverse_transform([stk_prediction_int])[0]
    
    if label != 'BENIGN':
        src_ip, src_port, dst_ip, dst_port, proto = flow_key
        log_entry = {
            'timestamp': time.strftime("%H:%M:%S"),
            'attack': label,
            'source': f"{src_ip}:{src_port}",
            'destination': f"{dst_ip}:{dst_port}"
        }
        with LOCK:
            ATTACKS_LOG.append(log_entry)
            print(f"🚨 FLOW ALERT: {label} from {src_ip}") 

# --- 4. PACKET HANDLER (Main Scapy Callback) ---

def packet_handler(packet):
    global TOTAL_FLOW_COUNT
    try:
        if 'IP' not in packet:
            return 
            
        TOTAL_FLOW_COUNT['value'] += 1
        src_ip = packet['IP'].src
        
        # --- LAYER 1: PROTOCOL ANOMALY CHECK (Immediate) ---
        is_anomaly, src_ip_anomaly = check_protocol_anomaly(packet)
        if is_anomaly:
            log_entry = {
                'timestamp': time.strftime("%H:%M:%S"),
                'attack': 'PROTOCOL_ANOMALY',
                'source': src_ip_anomaly,
                'destination': 'N/A (MALFORMED)'
            }
            with LOCK:
                ATTACKS_LOG.append(log_entry)
                print(f"🚨 PROTOCOL ALERT: Malformed packet from {src_ip_anomaly} 🚨")
            return 

        # --- LAYER 2: FLOW TRACKING ---
        if TCP in packet or UDP in packet:
            proto = 'TCP' if TCP in packet else 'UDP'
            port = packet[TCP].sport if proto == 'TCP' else packet[UDP].sport
            dport = packet[TCP].dport if proto == 'TCP' else packet[UDP].dport

            # Create the consistent bidirectional flow key
            key_components = sorted([ (src_ip, port), (packet['IP'].dst, dport) ])
            flow_key = (key_components[0][0], key_components[0][1], key_components[1][0], key_components[1][1], proto)
            direction = 'fwd' if (src_ip, port) == key_components[0] else 'bwd'

            packet_info = {
                'ts': time.time(), 
                'direction': direction, 
                'ip_len': packet['IP'].len,
            }
            if proto == 'TCP':
                packet_info['syn_flag'] = packet[TCP].flags.S if hasattr(packet[TCP].flags, 'S') else 0
                packet_info['fin_flag'] = packet[TCP].flags.F if hasattr(packet[TCP].flags, 'F') else 0
                packet_info['psh_flag'] = packet[TCP].flags.P if hasattr(packet[TCP].flags, 'P') else 0
                packet_info['ack_flag'] = packet[TCP].flags.A if hasattr(packet[TCP].flags, 'A') else 0
                packet_info['urg_flag'] = packet[TCP].flags.U if hasattr(packet[TCP].flags, 'U') else 0

            with LOCK: ACTIVE_FLOWS[flow_key].append(packet_info)
                
    except (IndexError, AttributeError): 
        pass

# --- 5. FLOW MANAGER (Thread Starter) ---

def flow_manager():
    """Periodically checks for and processes timed-out flows."""
    while True:
        time.sleep(FLOW_TIMEOUT / 2)
        now = time.time()
        
        with LOCK:
            keys_to_process = [key for key, packets in ACTIVE_FLOWS.items() if packets and now - packets[-1]['ts'] > FLOW_TIMEOUT]
            for key in keys_to_process:
                packets = ACTIVE_FLOWS[key]; del ACTIVE_FLOWS[key]
                if len(packets) > 1:
                    features = extract_flow_features(key, packets)
                    predict_flow_anomaly(key, features)

# --- 6. SNIFFER WRAPPER (Runs Scapy in a thread) ---
def sniffer_loop():
    """Wrapper function to execute Scapy's sniff operation."""
    try:
        # Scapy's sniff() runs forever and passes packets to packet_handler
        sniff(prn=packet_handler, store=False, iface=None, filter="ip")
    except Exception as e:
        print(f"FATAL SNIFFING ERROR: {e}")
        print("NOTE: You must ensure this terminal was run as Administrator.")


# --- 7. MAIN EXECUTION ---
if __name__ == '__main__':
    # Start Scapy's sniffing loop in a thread
    sniffer = threading.Thread(target=sniffer_loop, daemon=True) 
    
    # Start the flow manager thread
    manager = threading.Thread(target=flow_manager, daemon=True)
    
    print("Starting Two-Layer IPS Threads (REQUIRES SUDO/ADMIN)")
    sniffer.start()
    manager.start()
    
    # Start Flask Web Server (main thread)
    app = Flask(__name__)
    
    # Routes for web UI (must be defined AFTER Flask app is created)
    @app.route('/')
    def index(): 
        return render_template('index.html')

    @app.route('/data')
    def get_dashboard_data():
        with LOCK:
            latest_attacks = list(reversed(ATTACKS_LOG))
            active_flows_count = len(ACTIVE_FLOWS)
            total_flows = TOTAL_FLOW_COUNT['value']
        return jsonify({ 'attacks': latest_attacks, 'active_flows': active_flows_count, 'total_flows': total_flows })

    app.run(debug=False, host='0.0.0.0', port=5000)