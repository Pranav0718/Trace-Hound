# 🧬 Threat Fingerprint: TFC-B001-B002-B003-B004-B005-B006-B007-B008

## 🚩 Matched Behaviors:
### 🔹 Encoded PowerShell
- Technique: `T1059.001`
- Tactic: Execution
- MITRE Link: https://attack.mitre.org/techniques/T1059/001/
- Description: Detects obfuscated PowerShell usage via encoded command

### 🔹 Certutil Download
- Technique: `T1105`
- Tactic: Command and Control
- MITRE Link: https://attack.mitre.org/techniques/T1105/
- Description: Detects use of certutil to download remote files

### 🔹 Registry Run Key Persistence
- Technique: `T1547.001`
- Tactic: Persistence
- MITRE Link: https://attack.mitre.org/techniques/T1547/001/
- Description: Detects persistence via Run key modification

### 🔹 Procdump LSASS Dump
- Technique: `T1003.001`
- Tactic: Credential Access
- MITRE Link: https://attack.mitre.org/techniques/T1003/001/
- Description: Detects credential dumping via procdump.exe on LSASS

### 🔹 WMIC Remote Execution
- Technique: `T1047`
- Tactic: Execution
- MITRE Link: https://attack.mitre.org/techniques/T1047/
- Description: Detects remote execution using WMIC

### 🔹 Suspicious PowerShell Flags
- Technique: `T1059.001`
- Tactic: Execution
- MITRE Link: https://attack.mitre.org/techniques/T1059/001/
- Description: Detects stealthy PowerShell execution with hidden flags

### 🔹 Scheduled Task Creation
- Technique: `T1053.005`
- Tactic: Persistence
- MITRE Link: https://attack.mitre.org/techniques/T1053/005/
- Description: Detects task scheduling for persistence

### 🔹 RDP Session Hijacking
- Technique: `T1563.002`
- Tactic: Lateral Movement
- MITRE Link: https://attack.mitre.org/techniques/T1563/002/
- Description: Detects local RDP session hijack via tscon.exe

