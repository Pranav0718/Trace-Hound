import streamlit as st
import re
import yaml
from graphviz import Digraph

# Load behavior patterns from YAML


def load_patterns(path="patterns.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

# Match log data to patterns


def match_patterns(log_data, patterns):
    matched = []
    for p in patterns:
        if re.search(p["pattern"], log_data):
            matched.append({
                "id": p.get("id", "B000"),
                "name": p.get("name", "Unknown Behavior"),
                "technique": p.get("technique", "N/A"),
                "tactic": p.get("tactic", "Not Specified"),
                "mitre_link": p.get("mitre_link", "#"),
                "description": p.get("description", ""),
                # ✅ Include pattern for Sigma rule
                "pattern": p.get("pattern", "")
            })
    return matched

# Generate unique fingerprint


def generate_fingerprint(matched):
    ids = [b["id"] for b in matched]
    return "TFC-" + "-".join(ids) if ids else "TFC-None"

# Generate Markdown report


def generate_report(fingerprint, matched, filename="tracehound_report.md"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# 🧬 Threat Fingerprint: {fingerprint}\n\n")
        f.write("## 🚩 Matched Behaviors:\n")
        for m in matched:
            f.write(f"### 🔹 {m['name']}\n")
            f.write(f"- Technique: `{m['technique']}`\n")
            f.write(f"- Tactic: {m['tactic']}\n")
            f.write(f"- MITRE Link: {m['mitre_link']}\n")
            f.write(f"- Description: {m['description']}\n\n")

# Generate Sigma rule


def generate_sigma_rule(fingerprint, matched, filename="tracehound_sigma.yml"):
    rule = {
        "title": f"TraceHound Detection - {fingerprint}",
        "id": fingerprint,
        "description": "Auto-generated detection rule based on matched behaviors",
        "status": "experimental",
        "logsource": {
            "product": "windows",
            "service": "sysmon"
        },
        "detection": {
            "selection": {},
            "condition": "selection"
        },
        "level": "medium"
    }

    commandline_patterns = [p["pattern"] for p in matched if "pattern" in p]
    rule["detection"]["selection"]["CommandLine|contains"] = commandline_patterns

    with open(filename, "w", encoding="utf-8") as f:
        yaml.dump(rule, f)


# UI setup
st.set_page_config(page_title="TraceHound", layout="centered")
st.title("🔍 TraceHound: Threat Behavior Fingerprinter")

uploaded_file = st.file_uploader(
    "Upload a Sysmon log file (.txt)", type=["txt"])

if uploaded_file is not None:
    logs = uploaded_file.read().decode("utf-8", errors="ignore")
    patterns = load_patterns()
    matched = match_patterns(logs, patterns)
    fingerprint = generate_fingerprint(matched)

    st.markdown(f"### 🧬 Threat Fingerprint: `{fingerprint}`")

    if matched:
        st.markdown("### 🚩 Matched Behaviors:")
        for m in matched:
            st.markdown(f"""
            ### 🔹 {m['name']}  
            - **Technique:** `{m['technique']}`  
            - **Tactic:** {m['tactic']}  
            - **MITRE Link:** [View Technique]({m['mitre_link']})  
            - **Description:** {m['description']}
            """)

        # 🔗 Attack Chain Visualization
        st.markdown("### 🔗 Attack Chain Visualization")

        dot = Digraph()
        for i, m in enumerate(matched):
            node_id = m['id']
            label = f"{m['name']}\n{m['technique']}"
            dot.node(node_id, label=label, shape="box")
            if i > 0:
                dot.edge(matched[i - 1]['id'], node_id)
        st.graphviz_chart(dot)

        # 📄 Report Export
        generate_report(fingerprint, matched)
        with open("tracehound_report.md", "r", encoding="utf-8") as f:
            st.download_button(
                label="📥 Download Report (Markdown)",
                data=f.read(),
                file_name="tracehound_report.md",
                mime="text/markdown"
            )

        # 🛡 Sigma Rule Export
        generate_sigma_rule(fingerprint, matched)
        with open("tracehound_sigma.yml", "r", encoding="utf-8") as f:
            st.download_button(
                label="🛡 Download Sigma Rule",
                data=f.read(),
                file_name="tracehound_sigma.yml",
                mime="text/yaml"
            )

    else:
        st.info("✅ No known threat behaviors detected.")
