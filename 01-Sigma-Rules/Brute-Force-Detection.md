# Brute Force Detection

## Attack Description

A brute force attack occurs when an attacker repeatedly attempts to guess the password for a single user account by trying many different passwords until one succeeds or the account becomes locked.

---

## Why This Matters

Brute force attacks are one of the most common techniques used to gain unauthorized access to user accounts.

If successful, an attacker may gain access to sensitive company resources.

---

## Detection Logic (Plain English)

Generate a High severity alert when:

- Multiple failed login attempts occur against the same user account.
- The attempts occur within a short period of time.
- The attempts originate from the same source.
- A successful login immediately follows the failed login attempts.

---

## Windows Event IDs

- Event ID 4625 – Failed Logon
- Event ID 4624 – Successful Logon

---

## Investigation Steps

An analyst should verify:

- Whether the login originated from a known device.
- Whether the source IP address is expected.
- Whether the login occurred during business hours.
- Whether the user recently reset their password.
- What actions occurred after the successful login.

---

## Severity

High

---

## Lessons Learned

A single failed login is usually not suspicious.

A sequence of failed logins followed by a successful login represents a behavioral pattern that deserves investigation.

---

# Sigma Rule

```yaml
title: Multiple Failed Logins Followed by Successful Logon

id: REPLACE-WITH-UUID

status: experimental

description: Detects possible brute force attacks where multiple failed logins are followed by a successful login.

author: Collen Macamo

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
