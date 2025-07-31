import streamlit as st
import re
import yaml
import json

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
                "id": p["id"],
                "name": p["name"],
                "technique": p["technique"],
                "description": p["description"]
            })
    return matched

# Generate unique fingerprint


def generate_fingerprint(matched):
    ids = [b["id"] for b in matched]
    return "TFC-" + "-".join(ids) if ids else "TFC-None"


# UI
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
            - **{m['name']}** (`{m['technique']}`)  
              {m['description']}
            """)
    else:
        st.info("No known threat behaviors detected.")
