# Case 004 – Event ID 4672 (Special Privileges Assigned)

## Objective

This case documents Event ID 4672 and explains how Windows records the assignment of special privileges to privileged accounts. The objective is to demonstrate how SOC analysts distinguish between expected administrative activity and potentially malicious use of privileged accounts.

---

## Event Summary

| Field | Value |
|-------|-------|
| Event ID | 4672 |
| Event Name | Special Privileges Assigned to New Logon |
| Account | SYSTEM |
| Date | 21 July 2026 |
| Time | 14:05 |

---

## Evidence

See:

- Screenshot-01-EventViewer.png

---

## What Happened?

Windows generated Event ID 4672 after the SYSTEM account successfully authenticated and was assigned its built-in administrative privileges.

These privileges are required for many operating system services and are expected during normal Windows operation.

---

## Important Fields

### Event ID

4672

Meaning:

Windows assigned special administrative privileges to the newly authenticated session.

---

### Account

SYSTEM

Meaning:

The built-in operating system account responsible for running critical Windows services.

---

### Privileges Observed

The SYSTEM account received several high-level Windows privileges, including:

- Debug processes
- Backup files
- Restore files
- Take ownership of objects
- Load drivers
- Impersonate users

These privileges are expected for the SYSTEM account.

---

## Analyst Assessment

This event is considered legitimate.

Reasons:

- The account is SYSTEM.
- SYSTEM normally receives these privileges.
- No suspicious child processes were observed.
- No evidence of privilege abuse followed the event.

---

## Detection Engineering Notes

Event ID 4672 rarely indicates malicious activity by itself.

However, analysts should investigate when:

- A non-administrative account receives these privileges.
- Administrative logons occur outside normal business hours.
- PowerShell, cmd.exe, certutil.exe, or other administrative tools execute immediately afterward.
- Windows Defender or security controls are modified.

Correlation with additional events significantly improves detection accuracy.

---

## Investigation Questions

If this event appeared suspicious, I would investigate:

- Which account received the privileges?
- Should that account normally have administrative rights?
- What processes started immediately afterward?
- Were new users or services created?
- Were security controls modified?
- Were sensitive files accessed?

---

## Conclusion

This event represents expected Windows behavior for the SYSTEM account.

No escalation is recommended based on this event alone.

Further investigation would only be required if additional suspicious activity occurred immediately afterward.
