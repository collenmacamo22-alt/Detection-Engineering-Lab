# Detection Engineering with Sigma Rules

## Overview

This project demonstrates my understanding of Detection Engineering by designing and documenting detection logic for common Windows attack techniques using Sigma rules.

Rather than focusing only on writing Sigma syntax, this repository emphasizes the analytical thinking behind detection engineering, including attack behavior, event correlation, investigation methodology, severity classification, and MITRE ATT&CK mapping.

---

## Objectives

- Design practical detection logic for common attacks.
- Learn how attackers abuse legitimate Windows tools.
- Reduce false positives through event correlation.
- Practice translating attack scenarios into Sigma detections.
- Improve SOC investigation and incident response skills.

---

## Repository Structure

```
01-Sigma-Rules/
    Brute-Force-Detection.md
    Password-Spraying.md
    Suspicious-PowerShell-Execution.md
    USB-Device-Detection.md

02-Attack-Scenarios/
    PowerShell-Malware-Attack.md

03-Lessons-Learned/
    Key-Lessons.md

04-References/
    References.md
```
## Investigation Case Files

The following case studies demonstrate how Windows Security Events were analyzed from the perspective of a SOC analyst.

| Case | Description |
|------|-------------|
| Case 001 | Event ID 4624 – Interactive User Logon |
| Case 002 | Event ID 4624 – Service Logon |
| Case 003 | Event ID 4625 – Failed Logon *(Coming Soon)* |
| Case 004 | Event ID 4672 – Special Privileges Assigned *(Coming Soon)* |

---

## Skills Demonstrated

- Detection Engineering
- Sigma Rule Development
- Windows Event Analysis
- Windows Security Event IDs
- Incident Response
- Threat Hunting
- MITRE ATT&CK
- PowerShell Detection
- Windows Process Analysis
- Event Correlation
- Security Operations (SOC)

---

## MITRE ATT&CK Concepts Covered

- Initial Access
- Execution
- Command and Scripting Interpreter (PowerShell)
- Living off the Land (LotL)
- Ingress Tool Transfer
- Defense Evasion

---

## Key Learning Outcomes

Through this project I learned that:

- Individual Windows events rarely indicate malicious activity by themselves.
- Context and event correlation significantly improve detection accuracy.
- Parent-child process relationships provide valuable investigation context.
- Legitimate Windows tools can be abused by attackers.
- Well-designed detection rules reduce analyst workload and improve response times.

---

## Future Improvements

Future versions of this repository will include:

- Additional Sigma detection rules
- Sysmon-based detections
- Wazuh detection rules
- Microsoft Defender for Endpoint detections
- Splunk detection queries
- Elastic SIEM detection rules

---

## Author

**Siphamandla Collen Macamo**

CompTIA Security+ Certified

Cybersecurity | Detection Engineering | SOC Analysis | Threat Detection
