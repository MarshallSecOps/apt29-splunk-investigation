# APT29 Splunk Investigation

This repository documents my end-to-end investigation of the APT29 evaluation dataset using Splunk.  
It includes detection queries, decoded payloads, an attack timeline, MITRE ATT&CK mapping, and a written incident report.

---

## 🧪 Lab Overview

- **SIEM:** Splunk Enterprise (Docker on macOS, Apple Silicon)
- **Dataset:** OTRF Security Datasets — `windows/apt29` (Day 1 and Day 2)
- **Events ingested:** ~800k
- **Focus:** Obfuscated PowerShell, LSASS credential dumping, lateral movement, and covert WMI exfiltration.

---

## 📂 Contents

- `detections/` — SPL queries used to detect malicious activity  
- `decoded_payloads/` — Decoded PowerShell payloads recovered from EncodedCommand  
- `timeline/` — Attack timeline based on log evidence  
- `mitre_mapping/` — Mapping of observed activity to MITRE ATT&CK  
- `report/` — Full incident report in markdown  
- `screenshots/` — Screenshots from Splunk and CyberChef  

---

## 🚨 Key Detections

### 1. Obfuscated PowerShell Execution
Detects PowerShell launched with:
- `-exec bypass`
- `-windowstyle hidden`
- EncodedCommand

**File:** [`detections/01_powershell_obfuscated.spl`](detections/01_powershell_obfuscated.spl)

---

### 2. LSASS Credential Dumping
Flags suspicious LSASS access by non-system accounts across multiple hosts.

**File:** [`detections/02_lsass_credential_dumping.spl`](detections/02_lsass_credential_dumping.spl)

---

## ✨ Highlight: Decoded APT29 Credential Theft Script

A single EncodedCommand payload decodes to a script that:

- Downloads `m.exe` from `http://192.168.0.4:8080/m`
- Executes Mimikatz commands (`privilege::debug`, `sekurlsa::logonpasswords`)
- Extracts plaintext passwords from LSASS output
- Base64-encodes results
- Stores them via WMI (`Set-WmiInstance`) as a covert exfiltration mechanism

**Decoded payload:**  
[`decoded_payloads/apt29_day2_powershell_payload_decoded.ps1`](decoded_payloads/apt29_day2_powershell_payload_decoded.ps1)

---

## 🗺️ MITRE ATT&CK Mapping

Full mapping available in:  
[`mitre_mapping/mitre_mapping.md`](mitre_mapping/mitre_mapping.md)

---

## 📝 Report

Full incident report:  
[`report/apt29_incident_report.md`](report/apt29_incident_report.md)

---

## 🧠 Learnings & Reflections

This investigation reinforced key DFIR concepts:

- Full decoding of obfuscated PowerShell is essential — many stages hide inside a single payload.
- Credential access often precedes lateral movement, and correlating timestamps proves attacker flow.
- WMI/WinRM can blend with normal enterprise noise — parent-child process relationships reveal intent.
- MITRE ATT&CK mapping helps clarify attacker objectives and strengthens incident reporting.
- SPL queries improve through iterative refinement to reduce noise and surface real attack behavior.

---

## 🛠️ Skills Demonstrated

- Threat hunting in Splunk (large dataset: ~800k events)
- Detection of obfuscated PowerShell activity
- Decoding and analysing malicious PowerShell payloads
- Credential dumping analysis (LSASS + Mimikatz)
- WMI/WinRM lateral movement investigation
- MITRE ATT&CK technique mapping
- SPL detection engineering
- Forensic timeline reconstruction
- Professional DFIR-style reporting

---

## 🚀 Next Steps / Enhancements

Future improvements include:

- Building Sigma rules from SPL detections  
- Replaying the attack using Sysmon + Windows endpoints  
- Creating YARA rules for payload identification  
- Building a Splunk dashboard for real-time detection  
- Visualising the ATT&CK mapping using ATT&CK Navigator  

---

## ✔️ Summary

This project demonstrates practical SOC and DFIR capabilities — from decoding attacker payloads and analysing LSASS credential theft, to mapping behaviours to MITRE ATT&CK and producing a professional security investigation report.


