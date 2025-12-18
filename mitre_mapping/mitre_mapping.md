## MITRE ATT&CK Mapping – APT29 Splunk Investigation

This table maps observed activity in the APT29 evaluation dataset to MITRE ATT&CK techniques, with direct evidence from collected Splunk screenshots and decoded payloads.

| Technique | ID | Evidence |
|---------|----|---------|
| PowerShell | T1059.001 | Obfuscated PowerShell execution using `-ExecutionPolicy Bypass`,<br> `-WindowStyle Hidden`, and `-EncodedCommand`.<br>**Evidence:**<br> [01_splunk_powershell_obfuscated.png](Screenshots/01_splunk_powershell_obfuscated.png) |
| Obfuscated / Encrypted Payload | T1027 | Base64-encoded PowerShell command identified and decoded from process command line activity.<br>**Evidence:**<br> [02_splunk_encoded_powershell_detection_1.png](Screenshots/02_splunk_encoded_powershell_detection_1.png),<br> [03_cyberchef_decoded_payload_1.png](Screenshots/03_cyberchef_decoded_payload_1.png) |
| Ingress Tool Transfer | T1105 | PowerShell payload downloads `m.exe` from `http://192.168.0.4:8080/m` as observed in decoded script.<br>**Evidence:**<br> [03_cyberchef_decoded_payload_1.png](Screenshots/03_cyberchef_decoded_payload_1.png) |
| OS Credential Dumping: LSASS | T1003.001 | Suspicious LSASS access activity detected across multiple hosts, consistent with credential dumping behavior.<br>**Evidence:**<br> [04_splunk_lsass_credential_dumping.png](Screenshots/04_splunk_lsass_credential_dumping.png) |
| Remote Services: WinRM | T1021.006 | WinRM activity reviewed and compared against baseline behavior to contextualize subsequent malicious child process execution.<br>**Evidence:**<br> [05_splunk_winrm_activity_baseline.png](Screenshots/05_splunk_winrm_activity_baseline.png) |
| Windows Management Instrumentation | T1047 | Child process execution spawned from `wsmprovhost.exe`, confirming remote execution via WinRM/WMI context.<br>**Evidence:**<br> [05b_splunk_winrm_child_process_execution.png](Screenshots/05b_splunk_winrm_child_process_execution.png) |
| Indicator Removal on Host (Not Observed) | T1070 | Log clearing activity was investigated; only benign behavior observed,<br> no malicious log deletion detected.<br>**Evidence:**<br> [06_splunk_log_clearing_benign.png](Screenshots/06_splunk_log_clearing_benign.png) |
| Persistence via Registry Run Keys (Not Observed) | T1547.001 | Registry locations reviewed for persistence mechanisms; only expected benign entries identified.<br>**Evidence:**<br> [07_splunk_registry_persistence_expected.png](Screenshots/07_splunk_registry_persistence_expected.png) |
