# apt29-splunk-investigation

This repository documents my end-to-end investigation of the APT29 evaluation dataset using Splunk.
It includes detection queries, decoded payloads, an attack timeline, MITRE ATT&CK mapping, and a written incident report.

## 🧪 Lab Overview

- **SIEM:** Splunk Enterprise (Docker on macOS, Apple Silicon)
- **Dataset:** OTRF Security Datasets – `windows/apt29` (Day 1 and Day 2)
- **Events ingested:** ~800k
- **Focus:** PowerShell abuse, credential dumping (LSASS), and covert exfiltration.

## 🔍 Contents

- `detections/` – SPL queries used to detect malicious activity.
- `decoded_payloads/` – Decoded PowerShell payloads recovered from EncodedCommand.
- `timeline/` – Attack timeline based on log evidence.
- `mitre_mapping/` – Mapping of observed activity to MITRE ATT&CK.
- `report/` – Full incident report in markdown.
- `screenshots/` – Screenshots from Splunk and CyberChef.

## 🚨 Key Detections

1. **Obfuscated PowerShell Execution**

   - Detects PowerShell with `-exec bypass`, `-windowstyle hidden`, and EncodedCommand.
   - File: [`detections/01_powershell_obfuscated.spl`](detections/01_powershell_obfuscated.spl)

2. **LSASS Credential Dumping**

   - Flags suspicious LSASS access by non-system accounts across multiple hosts.
   - File: [`detections/02_lsass_credential_dumping.spl`](detections/02_lsass_credential_dumping.spl)

## 🧬 Highlight: Decoded APT29 Credential Theft Script

One EncodedCommand payload decodes to a script which:

- Downloads `m.exe` from `http://192.168.0.4:8080/m`
- Executes Mimikatz commands `privilege::debug` and `sekurlsa::logonpasswords`
- Extracts plaintext passwords from the output
- Encodes them in Base64
- Stores them using WMI (`Set-WmiInstance`) as a covert exfiltration mechanism

See: [`decoded_payloads/apt29_day2_powershell_payload_decoded.ps1`](decoded_payloads/apt29_day2_powershell_payload_decoded.ps1).

## 🗺️ MITRE ATT&CK

A full mapping is available in [`mitre_mapping/mitre_mapping.md`](mitre_mapping/mitre_mapping.md).

## 📄 Report

The full written incident report is in [`report/apt29_incident_report.md`](report/apt29_incident_report.md).

