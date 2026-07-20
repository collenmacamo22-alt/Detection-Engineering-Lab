# Password Spraying Detection

## Attack Description

Password spraying is an authentication attack in which an attacker attempts a small number of commonly used passwords against many different user accounts. Unlike brute-force attacks, password spraying avoids account lockouts by targeting multiple users instead of repeatedly attacking a single account.

## Why This Matters

Password spraying is commonly used to gain initial access to enterprise environments. Because the attacker distributes login attempts across many accounts, traditional account lockout controls may not detect the attack.

## Detection Logic

Generate a High severity alert if:

- The same source IP address generates failed login attempts against multiple user accounts.
- The login attempts occur within a ten-minute time window.
- The number of targeted user accounts exceeds a defined threshold.

Increase the alert severity to Critical if:

- A successful login follows the failed attempts.
- The successful login originates from an unfamiliar location.
- The source IP has been associated with previous malicious activity.
- The compromised account is privileged.

## Windows Event IDs

| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon |
| 4624 | Successful logon |

## Investigation Steps

1. Identify all targeted user accounts.
2. Determine the source IP address.
3. Review authentication history.
4. Determine whether any accounts successfully authenticated.
5. Disable compromised accounts if necessary.
6. Block the source IP if confirmed malicious.
7. Review additional authentication logs for lateral movement.

## Severity

Default Severity: High

Escalate to Critical when a successful login or privileged account compromise is observed.

## Lessons Learned

- Password spraying targets many accounts rather than one.
- Time correlation is critical for detection.
- Source IP correlation significantly improves confidence.
- Successful authentication following widespread failures should be investigated immediately.

## Sigma Rule

```yaml
title: Password Spraying Detection

id: REPLACE-WITH-UUID

status: experimental

description: Detects multiple failed logins against different user accounts from the same source IP.

author: Collen Macamo

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4625

  condition: selection

level: high
```
