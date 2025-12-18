# APT29 Splunk Investigation

This repository documents an end-to-end investigation of the APT29 evaluation dataset using Splunk.  
It includes detection queries, decoded PowerShell payloads, an evidence-backed attack timeline, MITRE ATT&CK mapping, and a full DFIR-style incident report.

---

## Lab Overview

- **SIEM:** Splunk Enterprise (Docker on macOS, Apple Silicon)
- **Dataset:** OTRF Security Datasets — `windows/apt29` (Day 1 and Day 2)
- **Events ingested:** ~800,000
- **Focus areas:**
  - Obfuscated PowerShell execution
  - LSASS credential dumping (Mimikatz-style)
  - WinRM/WMI lateral movement
  - Covert credential staging and persistence

---

## Repository Structure

- [screenshots/](screenshots/) — Screenshots from Splunk and CyberChef supporting findings
- [decoded_payloads/](decoded_payloads/) — Decoded PowerShell payloads recovered from EncodedCommand
- [detections/](detections/) — SPL queries used to detect malicious activity  
- [mitre_mapping/](mitre_mapping/) — Mapping of observed activity to MITRE ATT&CK
- [report/](report/) — Full written incident report
- [timeline/](timeline/) — Evidence-based attack timeline  
  
---

## Key Detections

### 1. Obfuscated PowerShell Execution

Detects PowerShell launched with execution bypass and encoded payloads.

Indicators include:
- `-ExecutionPolicy Bypass`
- `-WindowStyle Hidden`
- `-EncodedCommand`

**Detection:**  
[detections/01_powershell_obfuscated.spl](detections/01_powershell_obfuscated.spl)

---

### 2. LSASS Credential Dumping

Identifies suspicious LSASS access by non-system users across multiple hosts, consistent with Mimikatz usage.

**Detection:**  
[detections/03_lsass_credential_dumping.spl](detections/03_lsass_credential_dumping.spl)

---

### 3. WinRM / WMI Lateral Movement

Detects remote execution via WinRM and WMI using `wsmprovhost.exe` as the parent process.

**Detections:**  
- [detections/04_winrm_lateral_movement.spl](detections/04_winrm_lateral_movement.spl)  
- [detections/05b_splunk_winrm_child_process_execution.spl](detections/05b_splunk_winrm_child_process_execution.spl)

---

### 4. Persistence via Remote Local Account Creation

Detects local account creation executed remotely via WinRM/WMI context.  
This activity represents confirmed malicious persistence rather than benign system behaviour.

Observed command example:
- `net.exe user /add toby pamBeesly<3`

Detection:
- [detections/05b_splunk_winrm_child_process_execution.spl](detections/05b_splunk_winrm_child_process_execution.spl)

---

## Highlight: Decoded APT29 Credential Theft Script

A single EncodedCommand payload decodes to a PowerShell script that:

- Downloads `m.exe` from `http://192.168.0.4:8080/m`
- Executes Mimikatz commands:
  - `privilege::debug`
  - `sekurlsa::logonpasswords`
- Extracts plaintext credentials from LSASS memory
- Base64-encodes the output
- Stages stolen credentials via WMI using `Set-WmiInstance`

**Decoded payload:**  
[decoded_payloads/01_apt29_day2_powershell_payload_decoded.ps1](decoded_payloads/01_apt29_day2_powershell_payload_decoded.ps1)

---

## Evidence Collection

Key screenshots supporting findings:

👉 [screenshots/](screenshots/)

---

## MITRE ATT&CK Mapping

Full mapping of observed behavior to MITRE ATT&CK techniques is available here:

👉 [mitre_mapping/mitre_mapping.md](mitre_mapping/mitre_mapping.md)

---

## Incident Report

A complete DFIR-style incident report including timeline, findings, and conclusions:

👉 [report/apt29_incident_report.md](report/apt29_incident_report.md)

---

## Learnings & Reflections

This investigation reinforced several DFIR fundamentals:

- Full decoding of obfuscated PowerShell is essential — multiple attack stages were hidden in a single payload
- Credential access clearly preceded lateral movement
- Iterative SPL refinement is key to reducing noise while surfacing real attacker behavior
- WinRM/WMI activity blends into normal enterprise noise without parent-child correlation
- Persistence can masquerade as legitimate administrative behavior
- MITRE ATT&CK mapping strengthens reporting clarity

---

## Skills Demonstrated

- Threat hunting in Splunk (~800k events)
- SPL detection engineering
- PowerShell payload decoding and analysis
- LSASS credential dumping investigation
- WinRM/WMI lateral movement analysis
- Persistence detection
- MITRE ATT&CK technique mapping
- Forensic timeline reconstruction
- Professional DFIR reporting

---

## Next Steps / Enhancements

Potential future improvements:

- Converting SPL detections into Sigma rules
- Creating YARA rules for payload identification
- Continue modifying/enhancing a Splunk dashboard for real-time detection
- Visualizing ATT&CK coverage using ATT&CK Navigator

---

## Summary

This project demonstrates practical SOC and DFIR capabilities — from decoding attacker payloads and investigating LSASS credential theft, to identifying lateral movement, persistence, and producing a professional security investigation report.
