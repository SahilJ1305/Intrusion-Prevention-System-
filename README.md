# Intrusion Prevention System (IPS) — Windows (ML + Proxy + Packet Enforcement)


**Short:** A Windows-first IPS that captures network flows, classifies them using an ML model trained on **CICIDS2017**, automatically blocks high-confidence malicious sources via Windows Firewall, and **cleans application-layer content** (HTTP/files) through a mitmproxy sanitizer before re-delivery.


> See `docs/` for architecture diagrams and detailed notes.


## Quick links
- Worker: `worker/pydivert_worker.py`
- Model server: `model_server/server.py`
- Proxy addon: `proxy/sanitize_addon.py`
- Model training: `model/train_model.py`
- Demo runner: `deploy/run_demo.ps1`


## Quick start (dev)
1. Install prerequisites: Npcap, WinDivert, Python 3.9+, ClamAV (optional).
2. Create virtual env and install requirements for each component.
3. Place your trained model (`model.joblib`) into `model_server/`.
4. Run `uvicorn model_server.server:app --host 127.0.0.1 --port 8000`.
5. Run `mitmproxy -s proxy/sanitize_addon.py -p 8080` and configure a browser to use `localhost:8080` for demo.
6. Run `worker/pydivert_worker.py` as Administrator.


## License
Choose an appropriate open-source license (MIT recommended).
