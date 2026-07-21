# Case 003 – Event ID 4625 (Failed Logon)

## Objective

This case documents a failed Windows authentication attempt and demonstrates how failed logons form the foundation of brute-force detection.

---

## Event Summary

| Field | Value |
|-------|-------|
| Event ID | 4625 |
| Event Name | Failed Logon |
| Account | *(Quinton)* |
| Date | *(07/21/2026)* |
| Time | *(10:04 AM)* |

---

## Evidence

See:

- Screenshot-03-EventViewer.png

---

## What Happened?

Windows recorded a failed authentication attempt.

Unlike Event ID 4624, the user did not successfully authenticate.

This event commonly appears when:

- A user mistypes their password.
- An attacker guesses passwords.
- Automated password attacks occur.

---

## Important Fields

### Event ID

4625

Meaning:

Failed authentication.

---

### Account

The account Windows attempted to authenticate.

---

### Failure Reason

Explains why authentication failed.

Examples include:

- Unknown username
- Incorrect password
- Account locked
- Account disabled

---

## Analyst Assessment

A single failed logon is usually normal.

Employees frequently mistype passwords.

However, repeated Event ID 4625 events within a short period may indicate:

- Brute-force attacks
- Password spraying
- Credential guessing

---

## Detection Engineering Notes

This event directly supports the Brute Force Detection Sigma Rule.

The rule should correlate:

- Multiple Event ID 4625 events
- Same username
- Same source IP
- Short time window

This reduces false positives while improving detection quality.

---

## Investigation Questions

If this alert fired, I would investigate:

- How many failures occurred?
- Which account was targeted?
- Did a successful logon follow?
- Did the source IP change?
- Is the account privileged?

---

## Conclusion

A single Event ID 4625 is not sufficient evidence of an attack.

Multiple correlated failed logons should trigger further investigation.
