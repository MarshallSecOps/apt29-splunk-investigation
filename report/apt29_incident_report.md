# APT29 Incident Report – Splunk Lab

## 1. Executive Summary

This lab simulates an investigation into an APT29 intrusion using the public APT29 evaluation datasets ingested into Splunk.
The attacker leveraged obfuscated PowerShell, credential dumping against LSASS, and covert exfiltration via WMI.

**Key outcomes:**

- Built a Splunk lab in Docker and ingested ~800k APT29 events (Day1 & Day2).
- Identified malicious PowerShell activity used to stage and execute a credential-theft payload.
- Confirmed LSASS credential dumping across multiple hosts.
- Mapped observed behaviour to MITRE ATT&CK and developed reusable SPL detections.

## 2. Environment

- Splunk Enterprise 9.x in Docker (Apple Silicon, `--platform linux/amd64`)
- Dataset: OTRF Security Datasets – `windows/apt29` Day1 & Day2
- Host OS: macOS (M-series MacBook)

## 3. Attack Overview

Summarise in a few paragraphs what the attacker did, in your own words.

## 4. Detailed Findings

### 4.1 Malicious PowerShell Execution (T1059.001, T1027)

Explain:
- The `-exec bypass -noninteractive -windowstyle hidden` pattern
- The EncodedCommand block
- How you decoded it with CyberChef
- Link to: `detections/01_powershell_obfuscated.spl` and `decoded_payloads/...`

### 4.2 Credential Dumping via LSASS (T1003.001)

Explain:
- Multiple hosts with LSASS events in the same second
- Why that’s suspicious
- Query used: `detections/02_lsass_credential_dumping.spl`

### 4.3 Exfiltration via WMI (T1047, T1020)

Explain:
- `Set-WmiInstance` being used to store Base64 credentials
- Why this is a stealthy exfil method

_Add more sections as you analyse further parts of the logs (lateral movement, log clearing, persistence, etc.)._

## 5. Recommendations

List a few realistic recommendations, e.g.:

- Deploy detections for suspicious PowerShell command lines (encoded, hidden window, bypass).
- Monitor LSASS access from non-system accounts.
- Alert on use of `Set-WmiInstance` to unusual WMI classes (e.g., `Win32_AuditCode`).
- Enforce PowerShell Constrained Language Mode and script signing where possible.

## 6. Lessons Learned (for me as an analyst)

Describe what you learned:
- Working with Splunk + Docker
- Writing SPL
- Mapping to MITRE
- Decoding obfuscated payloads
