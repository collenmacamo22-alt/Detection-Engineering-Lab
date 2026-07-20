# Brute Force Detection

## Attack Description

A brute-force attack is a password attack in which an attacker repeatedly attempts different passwords against the same user account until the correct password is found. These attacks often generate numerous failed authentication events before a successful login.

## Why This Matters

Successful brute-force attacks can result in unauthorized access to user accounts, privilege escalation, data theft, or deployment of malware. Early detection reduces attacker dwell time and limits business impact.

## Detection Logic

Generate a High severity alert if:

- Five or more failed login attempts occur against the same user account.
- The failed attempts originate from the same source IP address.
- The failed attempts occur within a five-minute time window.
- The failed login attempts are followed by a successful login.

Increase the alert severity to Critical if:

- The successful login originates from an unfamiliar IP address.
- The login originates from another country.
- The login occurs outside normal business hours.
- The targeted account is privileged.

## Windows Event IDs

| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon |
| 4624 | Successful logon |

## Investigation Steps

1. Identify the affected account.
2. Determine the source IP address.
3. Review authentication history.
4. Verify whether MFA was enabled.
5. Determine whether the login was legitimate.
6. Reset credentials if compromise is confirmed.
7. Review surrounding security events for lateral movement or persistence.

## Severity

Default Severity: High

Escalate to Critical when additional indicators of compromise are present.

## Lessons Learned

- Individual events should not be analyzed in isolation.
- Context significantly improves detection accuracy.
- Time windows reduce false positives.
- Correlating multiple events produces stronger detections than monitoring single events.

## Sigma Rule

```yaml
title: Multiple Failed Logins Followed by Successful Logon

id: REPLACE-WITH-UUID

status: experimental

description: Detects possible brute-force attacks where multiple failed logins are followed by a successful login.

author: Siphamandla Collen Macamo

logsource:
  product: windows
  service: security

detection:
  failed_logins:
    EventID: 4625

  successful_login:
    EventID: 4624

  condition: failed_logins followed_by successful_login

level: high
```
