# 🔍 TraceHound

**TraceHound** is a threat hunting tool that parses log data, detects attacker behaviors, maps them to MITRE ATT&CK techniques, and generates a unique threat fingerprint.

Built with Python + Streamlit  
📊 Input: Sysmon/Redline logs  
🧬 Output: Fingerprint like `TFC-B001-B002`

## 🚀 Features

- Upload `.txt` logs
- Detect PowerShell abuse, LOLBins, persistence methods
- Map findings to MITRE techniques
- Output fingerprint + JSON summary
- Web app interface (Streamlit)

## 🖥 Run the Web App

```bash
python -m streamlit run app.py
```
