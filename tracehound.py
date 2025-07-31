import re
import yaml
import json

def load_patterns(path="patterns.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def load_logs(path="sysmon_logs.txt"):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

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

def generate_fingerprint(matched):
    ids = [b["id"] for b in matched]
    return "TFC-" + "-".join(ids)

def main():
    logs = load_logs()
    patterns = load_patterns()
    matched = match_patterns(logs, patterns)
    fingerprint = generate_fingerprint(matched)
    
    result = {
        "threat_fingerprint": fingerprint,
        "matches": matched
    }

    print("\n[+] Threat Fingerprint:", fingerprint)
    print("    Detected Behaviors:")
    for m in matched:
        print(f"    - {m['name']} ({m['technique']})")

    with open("tracehound_output.json", "w") as f:
        json.dump(result, f, indent=4)

    print("\n[+] Output saved to: tracehound_output.json")

if __name__ == "__main__":
    main()
