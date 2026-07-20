# USB Device Detection

## Attack Description

USB devices can be used to introduce malware, steal sensitive data, or bypass network-based security controls. While many USB devices are legitimate, unauthorized USB activity should be monitored because removable media remains a common attack vector.

## Why This Matters

Attackers may use USB devices to introduce ransomware, keyloggers, malware, or to exfiltrate sensitive company data. Monitoring USB insertions helps identify potential insider threats and unauthorized device usage.

## Detection Logic

Generate a Medium severity alert if:

- A removable USB storage device is connected to a company computer.

Increase the alert severity to High if:

- The USB device is not company-approved.
- Large amounts of data are copied.
- The device is connected outside business hours.
- The affected user has privileged access.
- Executable files are launched from the USB device.

Increase the alert severity to Critical if:

- Malware execution is observed.
- Sensitive files are copied to the USB device.
- Security controls are disabled following USB insertion.

## Windows Event IDs

| Event ID | Description |
|----------|-------------|
| 6416 | External device recognized |
| 4663 | Object Access (File Access) |
| 4688 | Process Creation |

## Investigation Steps

1. Identify the user who connected the device.
2. Determine whether the USB device is company-approved.
3. Review files accessed after insertion.
4. Identify any executables launched from the device.
5. Review file copy activity.
6. Determine whether sensitive information was accessed.
7. Isolate the device if malicious activity is confirmed.

## MITRE ATT&CK Mapping

- Initial Access
- Execution
- Collection
- Exfiltration

## Lessons Learned

- USB insertion alone is not malicious.
- Context determines whether activity is suspicious.
- User identity, timing, and file activity significantly increase confidence.
- Monitoring removable media reduces insider and malware risks.

## Sigma Rule

```yaml
title: USB Device Connected

id: REPLACE-WITH-UUID

status: experimental

description: Detects removable USB devices connected to Windows systems.

author: Siphamandla Collen Macamo

logsource:
  product: windows

detection:
  selection:
    EventID: 6416

  condition: selection

level: medium
```
