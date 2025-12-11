# MITRE ATT&CK Mapping – APT29 Splunk Investigation

This table maps observed activity in the APT29 evaluation logs to ATT&CK techniques.

| Technique                            | ID         | Evidence                                                                          |
|--------------------------------------|------------|-----------------------------------------------------------------------------------|
| PowerShell                           | T1059.001  | Obfuscated PowerShell with `-exec bypass`, `-windowstyle hidden`, EncodedCommand. |
| Obfuscated/Encrypted Payload         | T1027      | Base64-encoded PowerShell block decoded in `decoded_payloads/...`.                | 
| Ingress Tool Transfer                | T1105      | Download of `m.exe` from `http://192.168.0.4:8080/m`.                             |
| OS Credential Dumping: LSASS         | T1003.001  | LSASS access events across multiple hosts (`02_lsass_credential_dumping.spl`).    |
| Command and Control over HTTPS       | T1071.001  | Hidden C2 via encrypted web traffic                                               |
| Windows Management Instrumentation   | T1047      | Use of `Set-WmiInstance` in decoded payload for covert storage.                   |
| Exfiltration                         | T1020      | Base64-encoded credentials stored via WMI and retrievable by attacker.            |


