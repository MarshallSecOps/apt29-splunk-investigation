# APT29 Incident Report – Splunk Lab

## 1. Executive Summary

This investigation analyzes a simulated APT29 intrusion using the public OTRF APT29 evaluation datasets (Day 1 & Day 2) ingested into Splunk Enterprise.

The attacker leveraged obfuscated and encoded PowerShell, staged a credential-theft payload (`m.exe`), dumped credentials from LSASS, laterally moved across hosts using WMI/WinRM (`wsmprovhost.exe`), and established persistence via remote user account creation.

The investigation reconstructs the attack chain across multiple hosts using process creation telemetry, command-line analysis, and parent-child process correlation.

**Key outcomes:**

- Built a Splunk lab in Docker and ingested ~800k APT29 events (Day 1 & Day 2).
- Identified malicious PowerShell activity used to stage and execute a credential-theft payload.
- Confirmed LSASS credential dumping across multiple hosts.
- Traced lateral movement via WMI / WinRM (`wsmprovhost.exe`).
- Confirmed persistence via remote user account creation (`net.exe user /add`).
- Mapped attacker behavior to MITRE ATT&CK and developed reusable SPL detections.

---

## 2. Environment

- **SIEM:** Splunk Enterprise 9.x (Docker)
- **Dataset:** OTRF Security Datasets – `windows/apt29` (Day 1 & Day 2)
- **Host OS:** macOS (Apple Silicon)
- **Telemetry:** Windows process creation events (Sysmon-style)

---

## 3. Attack Overview

APT29 executed a structured multi-stage intrusion consisting of:

- Encoded & obfuscated PowerShell execution
- Payload download and staging (`m.exe`)
- LSASS credential dumping
- Lateral movement via WMI / WinRM
- Persistence via remote user account creation
- Credential processing and staging via WMI

No destructive log wiping was observed.

---

## 4. Detailed Findings & Attack Timeline

The following section documents the observed attacker activity in chronological order, based on Splunk telemetry collected from the APT29 evaluation dataset (Day 1 and Day 2). All timestamps are shown in UTC.

---

### 4.1 Initial Execution – Obfuscated PowerShell

**Time:** 2020-05-02 07:54  
**Host:** UTICA.dmevals.local  
**Stage:** Initial Execution  

An obfuscated PowerShell command was executed on the UTICA host. The command was launched with execution controls designed to evade detection and user visibility, including bypassing execution policy, disabling interactivity, hiding the window, and supplying an encoded command payload.

This execution pattern is consistent with attacker tradecraft for initial payload delivery and aligns with APT29-style PowerShell abuse.

**Observed Details:**
- PowerShell launched with `-ExecutionPolicy Bypass`
- Non-interactive, hidden window execution
- EncodedCommand parameter used to conceal payload

**Evidence:**
- `Screenshots/01_splunk_powershell_obfuscated.png`

**MITRE ATT&CK:**
- T1059.001 – PowerShell  
- T1027 – Obfuscated / Encrypted Payloads

---

### 4.2 Payload Staging – Secondary Tool Download

**Time:** 2020-05-02 07:55  
**Host:** UTICA.dmevals.local  
**Stage:** Payload Staging  

The encoded PowerShell payload retrieved a secondary executable (`m.exe`) from an attacker-controlled HTTP server. This marks the transition from initial execution to staging of tooling used for credential access and lateral movement.

Decoded payload analysis confirms that the download was intentional and automated as part of the attack chain.

**Observed Details:**
- HTTP download of `m.exe`
- Attacker-controlled server used for payload delivery
- Payload decoded and validated via CyberChef

**Evidence:**
- `Screenshots/02_splunk_encoded_powershell_detection_1.png`
- `Screenshots/03_cyberchef_decoded_payload_1.png`
- `decoded_payloads/01_apt29_day2_powershell_payload_decoded.ps1`

**MITRE ATT&CK:**
- T1105 – Ingress Tool Transfer  
- T1059.001 – PowerShell

---

### 4.3 Credential Access – LSASS Memory Access

**Time:** 2020-05-02 07:59  
**Hosts:** UTICA, NEWYORK, NASHUA  
**Stage:** Credential Access  

Credential dumping activity was observed across multiple hosts, involving access to LSASS memory. The activity is consistent with the use of Mimikatz-style techniques to extract credentials for privilege escalation and lateral movement.

The presence of similar behavior across several systems indicates the attacker successfully leveraged stolen credentials to expand access within the environment.

**Observed Details:**
- LSASS accessed for credential material
- Activity observed on multiple hosts
- Likely credential reuse to enable lateral movement

**Evidence:**
- `Screenshots/04_splunk_lsass_credential_dumping.png`

**MITRE ATT&CK:**
- T1003.001 – LSASS Memory

---

### 4.4 Lateral Movement – Remote Command Execution via WMI and WinRM

**Time:** 2020-05-02 07:59–08:13  
**Hosts:** UTICA, NEWYORK, NASHUA  
**Stage:** Lateral Movement  

The attacker leveraged Windows remote management technologies to execute commands across multiple hosts. PowerShell was launched remotely under non-interactive contexts associated with `wsmprovhost.exe` and `WmiPrvSE.exe`, confirming the use of WinRM and WMI for lateral movement.

This activity demonstrates post-compromise expansion using native Windows tooling, consistent with APT29 operational patterns.

**Observed Details:**
- Remote PowerShell execution via WinRM
- WMI used for process execution
- Non-interactive management contexts observed

**Evidence:**
- `Screenshots/05_splunk_winrm_activity_baseline.png`
- `Screenshots/05b_splunk_winrm_child_process_execution.png`

**MITRE ATT&CK:**
- T1021.006 – Windows Remote Management  
- T1021.003 – Windows Management Instrumentation  
- T1047 – Windows Management Instrumentation

---

### 4.5 Credential Dumping – Remote Execution of Tooling

**Time:** 2020-05-02 08:02  
**Host:** NEWYORK.dmevals.local  
**Stage:** Credential Access  

The staged executable (`m.exe`) was executed remotely on the NEWYORK host under a WinRM execution context. The behavior observed aligns with credential dumping workflows, further supporting the conclusion that the attacker was harvesting credentials to maintain access and facilitate movement.

**Observed Details:**
- `m.exe` executed remotely
- Parent process consistent with WinRM execution
- Credential access activity inferred

**Evidence:**
- `Screenshots/05b_splunk_winrm_child_process_execution.png`

**MITRE ATT&CK:**
- T1003.001 – LSASS Memory

---

### 4.6 Persistence – Local Account Creation

**Time:** 2020-05-02 08:18  
**Host:** SCRANTON.dmevals.local  
**Stage:** Persistence  

A new local user account was created on the SCRANTON host using the `net.exe` utility. The process was launched under a remote management parent process (`wsmprovhost.exe`), indicating the action was performed by the attacker rather than an interactive administrator.

This activity represents a confirmed persistence mechanism and contradicts earlier assumptions that no persistence was present in the dataset.

**Observed Details:**
- `net.exe user /add` command executed
- Account creation performed remotely
- Parent process associated with WinRM

**Evidence:**
- `Screenshots/05b_splunk_winrm_child_process_execution.png`

**MITRE ATT&CK:**
- T1136.001 – Create Account: Local Account


---

## 5. Payload Analysis

APT29 used a Base64-encoded PowerShell payload containing two logical stages.

### Stage 1 – Tool Download & Execution

- Downloads `m.exe` from attacker infrastructure
- Configures `ProcessStartInfo`
- Executes credential-theft tooling
- Redirects output for processing

**File:** `decoded_payloads/01_apt29_day2_powershell_payload_decoded.ps1`

### Stage 2 – Credential Processing & WMI Staging

- Parses output for credential strings
- Base64-encodes results
- Stores data via WMI (e.g., `Win32_AuditCode`)

**File:** `decoded_payloads/02_wmi_stage2_payload_decoded.ps1`  
**Evidence:** `Screenshots/03_cyberchef_decoded_payload_1.png`

---

## 6. Detection Logic (SPL Samples)

### Encoded PowerShell Execution

Detects PowerShell launched with encoded or obfuscated commands.

    index=main source="*apt29_day2.json"
    (CommandLine="*powershell*" OR CommandLine="*EncodedCommand*")
    | table _time Hostname User Image ParentImage CommandLine
    | sort _time

---

### LSASS Credential Dumping

Identifies suspicious access to LSASS consistent with credential dumping.

    index=main source="*apt29_day2.json"
    (TargetImage="*lsass.exe*" OR Image="*lsass.exe*")
    | table _time Hostname User Image GrantedAccess TargetImage
    | sort _time

---

### WMI / WinRM Lateral Movement

Detects lateral movement via WinRM and WMI using `wsmprovhost.exe`.

    index=main source="*apt29_day2.json"
    (Image="*wsmprovhost.exe*" OR ParentImage="*wsmprovhost.exe*" OR Image="*winrm.exe*" OR Image="*wsman.exe*")
    | table _time Hostname User Image ParentImage CommandLine
    | sort _time

---

### Persistence – Remote Local Account Creation

Detects persistence via local account creation executed remotely via WinRM/WMI context.

    index=main source="*apt29_day2.json"
    ParentImage="*wsmprovhost.exe"
    (EventID=1)
    | table _time Hostname User ParentImage Image CommandLine
    | sort _time

---

## 7. MITRE ATT&CK Coverage

| Tactic | Technique |
|---|---|
| Execution | T1059.001 – PowerShell |
| Defense Evasion | T1027 – Obfuscated / Encoded Files |
| Credential Access | T1003.001 – LSASS Memory |
| Lateral Movement | T1021.003 – Remote Services: WMI |
| Lateral Movement | T1021.006 – Remote Services: WinRM |
| Execution | T1047 – Windows Management Instrumentation |
| Command and Control | T1105 – Ingress Tool Transfer |
| Persistence | T1136.001 – Create Account: Local Account |
| Defense Evasion | T1070.001 – Indicator Removal: Clear Windows Event Logs (Not Observed) |

---

## 8. Learnings & Reflections

- Encoded payloads often contain multiple stages; full decoding is required to understand intent.
- Credential access frequently precedes lateral movement; correlating timestamps across hosts is critical.
- WinRM/WMI can be noisy; parent/child process analysis is the fastest way to reduce false positives.
- `net.exe user /add` executed under a WinRM context is a strong persistence signal.
- Mapping behaviors to MITRE ATT&CK improves clarity, defensibility, and interview-readiness.

---

## 9. Skills Demonstrated

- Threat hunting and timeline building in Splunk across large event volumes
- Obfuscated PowerShell detection and decoding (Base64 / UTF-16LE)
- Payload staging and execution tracking (`m.exe`)
- Credential dumping investigation (LSASS access patterns)
- Lateral movement tracing (WMI / WinRM via `wsmprovhost.exe`)
- Persistence identification via account creation
- MITRE ATT&CK mapping and documentation
- Authoring reusable SPL detections and evidence-backed reporting

---

## 10. Next Steps

- Convert key SPL detections into Sigma rules
- Validate detections in a live Sysmon-enabled Windows lab (reduce false positives)
- Build a Splunk dashboard for WinRM/WMI + account creation correlation
- Expand reporting with defensive controls (WinRM restrictions, PowerShell logging, LSASS protection)



