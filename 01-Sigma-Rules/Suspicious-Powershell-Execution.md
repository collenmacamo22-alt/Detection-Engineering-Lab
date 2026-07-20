# Suspicious PowerShell Execution

## Attack Description

PowerShell is a legitimate Windows administrative tool that is frequently abused by attackers to execute commands, download malicious payloads, establish persistence, and disable security controls without introducing custom malware.

## Why This Matters

Because PowerShell is trusted and widely used by administrators, malicious activity can blend into normal system administration. Detecting suspicious PowerShell behavior is critical for identifying post-compromise activity.

## Detection Logic

Generate a High severity alert if:

- PowerShell is launched.
- PowerShell immediately executes a command.
- The command downloads a file from an external source.
- The downloaded file is executed shortly afterward.

Increase the alert severity to Critical if:

- Windows Defender or another security product is disabled.
- The activity occurs outside business hours.
- The account is privileged.
- The source IP is unfamiliar or originates from another country.

## Windows Event IDs

| Event ID | Description |
|----------|-------------|
| 4688 | Process Creation |
| 4104 | PowerShell Script Block Logging |
| 1116 | Microsoft Defender Malware Detection (if available) |

## Investigation Steps

1. Identify the user account.
2. Review the PowerShell command line.
3. Determine what file was downloaded.
4. Calculate the file hash.
5. Check whether the file executed successfully.
6. Review child processes launched by PowerShell.
7. Determine whether persistence or lateral movement occurred.

## MITRE ATT&CK Mapping

- Execution
- Command and Scripting Interpreter (PowerShell)
- Ingress Tool Transfer
- Defense Evasion (if security controls are disabled)

## Lessons Learned

- PowerShell alone is not suspicious.
- Context determines whether PowerShell activity is malicious.
- Parent-child process relationships are valuable indicators.
- Correlating multiple events produces higher-confidence detections.

## Sigma Rule

```yaml
title: Suspicious PowerShell Download and Execution

id: REPLACE-WITH-UUID

status: experimental

description: Detects PowerShell downloading and executing external files.

author: Collen Macamo

logsource:
  product: windows

detection:
  selection:
    Image|endswith: '\powershell.exe'

  condition: selection

level: high
```
