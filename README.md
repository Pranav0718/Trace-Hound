# 🐾 TraceHound

**TraceHound** is a behavior-based threat hunting tool that analyzes Sysmon logs, identifies MITRE ATT&CK techniques, and generates actionable artifacts including:

- 🔹 Threat fingerprints (unique TTP chains)
- 📄 Markdown incident reports
- 🛡️ Sigma detection rules
- 🧬 YARA rules
- 🔗 Graph-based attack chain visualizations

> 🎯 Built for security analysts, red teamers, and threat hunters seeking fast pattern detection from log data.

---

### 🚀 Live Demo

👉 [Launch TraceHound on Streamlit Cloud](https://tracehound.streamlit.app/)

---

## 🔧 Features

- 🧠 Matches log patterns to MITRE ATT&CK techniques
- 📈 Graphs sequential attacker behavior (via Graphviz)
- 📄 One-click export of Markdown reports
- 🛡 Sigma rule generation for SIEM platforms
- 🧬 YARA rule generation for binary detection
- 🌐 Streamlit UI for interactive analysis

---

## 🖼 Screenshot
<img width="1306" height="484" alt="image" src="https://github.com/user-attachments/assets/64c91752-f71d-4b26-a6bf-03460b59a80d" />

![TraceHound UI Screenshot]

---

## 📦 Installation


git clone https://github.com/Pranav0718/Trace-Hound.git
cd Trace-Hound
pip install -r requirements.txt
streamlit run app.py
