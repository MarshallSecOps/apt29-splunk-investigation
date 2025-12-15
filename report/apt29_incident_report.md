# APT29 Incident Report – Splunk Lab

## 1. Executive Summary
This lab simulates an investigation into an APT29 intrusion using the public APT29 evaluation datasets ingested into Splunk.
The attacker leveraged obfuscated PowerShell, credential dumping against LSASS, lateral movement via WMI/WinRM, and covert credential exfiltration via WMI.

**Key outcomes:**

- Built a Splunk lab in Docker and ingested ~800k APT29 events (Day1 & Day2).
- Identified malicious PowerShell activity used to stage and execute a credential-theft payload.
- Confirmed LSASS credential dumping across multiple hosts.
- Mapped observed behaviour to MITRE ATT&CK and developed reusable SPL detections.

## 2. Environment

- Splunk Enterprise 9.x in Docker (Apple Silicon)
- Dataset: OTRF Security Datasets – `windows/apt29` Day1 & Day2
- Host OS: macOS (M-series MacBook)

## 3. Attack Overview

APT29 executed a multi-stage attack leveraging:
Encoded & obfuscated PowerShell
Downloaded tooling (m.exe)
LSASS credential dumping
WMI/WinRM lateral movement
WMI-based credential exfiltration
No malicious persistence or log clearing was observed.

## 4. Detailed Findings & Attack Timeline

| Time            | Host(s)                | Stage                        | Description                                                                         | Evidence                                                                                                                             | MITRE                       |
| --------------- | ---------------------- | ---------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- |
| **07:54**       | UTICA                  | Initial Execution            | Obfuscated PowerShell (EncodedCommand) executed with `-exec bypass`.                | `01_splunk_powershell_obfuscated.png`                                                                                                | T1059.001, T1027            |
| **07:55**       | UTICA                  | Payload Staging              | PowerShell downloads `m.exe` from attacker server and prepares Mimikatz execution.  | `02_splunk_encoded_powershell_detection_1.png`, `03_cyberchef_decoded_payload_1.png`, `01_apt29_day2_powershell_payload_decoded.ps1` | T1105, T1059.001            |
| **07:59**       | NEWYORK, NASHUA, UTICA | Credential Access            | Multiple LSASS access events across hosts using stolen credentials.                 | `04_splunk_lsass_credential_dumping.png`                                                                                             | T1003.001                   |
| **07:59–08:13** | UTICA, NEWYORK, NASHUA | Lateral Movement             | WMI/WinRM (`wsmprovhost.exe`) launches PowerShell remotely across multiple systems. | `05_splunk_winrm_lateral_movement.png`                                                                                               | T1021.003, T1059.001        |
| **08:13**       | UTICA                  | C2 & Credential Exfiltration | Mimikatz output parsed, Base64-encoded, and stored via WMI (`Win32_AuditCode`).     | `03_cyberchef_decoded_payload_1.png`, `02_wmi_stage2_payload_decoded.ps1`                                                            | T1059.001, T1003.001, T1047 |
| **N/A**         | All Hosts              | Log Clearing (Benign)        | `wevtutil.exe` activity traced to Azure GuestAgent — no malicious log deletion.     | `08_splunk_log_clearing_benign.png`                                                                                                  | T1070.001 (Not Observed)    |
| **N/A**         | All Hosts              | Persistence (Benign)         | Only normal Run/RunOnce entries found (Teams, Windows Defender, WebCache).          | `09_splunk_registry_persistence_expected.png`                                                                                        | T1547.001 (Not Observed)    |

## 5. Payload Analysis

One EncodedCommand → Two Functional Stages<br>
APT29 used a single Base64-encoded PowerShell payload that contained both Stage 1 and Stage 2 logic:

Stage 1:<br>
Tooling Download & Execution<br>
Downloads m.exe from attacker server<br>
Configures ProcessStartInfo<br>
Executes Mimikatz<br>
Redirects output<br>
File: 01_apt29_day2_powershell_payload_decoded.ps1

Stage 2:<br>
Credential Processing & WMI Exfiltration<br>
Searches Mimikatz output for credential strings<br>
Extracts password lines < 50 chars<br>
Base64-encodes data<br>
Stores via WMI (Win32_AuditCode)<br>
File: 02_wmi_stage2_payload_decoded.ps1, 03_cyberchef_decoded_payload_1.png

## 6. Detection Logic (SPL Samples)

Encoded PowerShell Execution:<br>
index=main source="*apt29_day2.json"<br>
(CommandLine="*powershell*" OR CommandLine="*EncodedCommand*")<br>
| table _time Hostname Account_Name Image CommandLine ParentImage<br>
| sort _time

LSASS Credential Dumping:<br>
index=main source="*apt29_day2.json"<br>
(TargetImage="*lsass.exe" OR Image="*lsass.exe")<br>
| table _time Hostname User Image GrantedAccess<br>
| sort _time

WMI / WinRM Lateral Movement:<br>
index=main source="*apt29_day2.json"<br>
(Image="*wsmprovhost.exe" OR ParentImage="*wsmprovhost.exe" OR Image="*winrm.exe" OR Image="*wsman.exe")<br>
| table _time Hostname User Image ParentImage CommandLine<br>
| sort _time

Benign Log Clearing:<br>
index=main source="*apt29_day2.json"<br>
(Image="*wevtutil.exe" OR CommandLine="*wevtutil*")<br>
| table _time Hostname User Image CommandLine ParentImage ProcessId<br>
| sort _time

Benign Registry Persistence:<br>
index=main source="*apt29_day2.json"<br>
(TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*" OR CommandLine="*reg add*")<br>
| table _time Hostname Account_Name Image CommandLine TargetObject ParentImage<br>
| sort _time

## 7. MITRE ATT&CK Coverage)
| Tactic            | Technique                     |
| ----------------- | ----------------------------- |
| Execution         | T1059.001 – PowerShell        |
| Defense Evasion   | T1027 – Obfuscation           |
| Credential Access | T1003.001 – LSASS Dumping     |
| Lateral Movement  | T1021.003 – WMI               |
| C2                | T1105 – Ingress Tool Transfer |
| Command Execution | T1047 – WMI Execution         |
| Persistence       | T1547.001 – *Not Observed*    |
| Log Clearing      | T1070.001 – *Not Observed*    |

## 8. Learnings & Reflections

This investigation reinforced key DFIR principles:

- Encoded payloads often contain multiple execution stages, and decoding them fully is critical.
- Credential access often precedes lateral movement, and correlating timestamps is essential to proving causality.
- WMI and WinRM can appear noisy in enterprise logs; filtering by parent-child process chains dramatically reduces noise.
- Attack chains frequently overlap in techniques — mapping to MITRE ATT&CK clarifies intent and strengthens reporting.
- Splunk queries benefit from iterative refinement to reduce false positives and highlight actual attacker behaviour.

This lab strengthened my ability to triage, decode, correlate, and document multi-host intrusions.

## 9. Skills Demonstrated

- Threat hunting in Splunk across ~800k events  
- Obfuscated PowerShell detection and decoding  
- Payload reverse engineering (Base64, UTF-16LE)  
- Lateral movement tracing (WMI, WinRM)  
- Credential dumping analysis (LSASS, Mimikatz)  
- MITRE ATT&CK mapping and documentation  
- Writing reusable SPL detections  
- Producing professional incident reports  
- Building defender-relevant insights from attacker behaviour  

## 10. Next Steps

To expand this investigation I plan to:

- Build Sigma rules based on my SPL detections  
- Recreate the attack in a lab using Sysmon + real Windows hosts  
- Develop YARA signatures for payload detection  
- Use ATT&CK Navigator to overlay all mapped techniques  
- Build a Splunk dashboard for automated detection of this behaviour  
