# Case 002 – Event ID 4624 (Service Logon)

## Objective

This case documents a Windows service authentication and explains why not every successful logon should be treated as suspicious.

---

## Event Summary

| Field | Value |
|-------|-------|
| Event ID | 4624 |
| Event Name | Successful Logon |
| Account | SYSTEM |
| Logon Type | 5 (Service) |
| Date | 21 July 2026 |
| Time | 12:06 |

---

## Evidence

See:

- Screenshot-02-EventViewer.png

---

## What Happened?

Windows recorded a successful logon performed by the built-in SYSTEM account.

Logon Type 5 indicates that Windows authenticated a service so that it could begin running.

This commonly occurs during normal operating system activity.

---

## Important Fields

### Event ID

4624

Meaning:

Successful authentication.

---

### Account

SYSTEM

Meaning:

Built-in Windows operating system account.

---

### Logon Type

5

Meaning:

Service Logon.

Windows authenticated a service rather than a human user.

---

## Analyst Assessment

No suspicious activity is identified.

Reasons:

- SYSTEM account is expected.
- Service Logon is normal Windows behavior.
- No malicious child processes observed.
- No evidence of privilege escalation.
- No suspicious sequence of events.

---

## Detection Engineering Notes

Although this event is legitimate, attackers occasionally abuse Windows services.

Additional investigation would be required if this event were immediately followed by:

- PowerShell execution
- cmd.exe
- certutil.exe
- Encoded PowerShell commands
- Windows Defender modifications

---

## Investigation Questions

If this event were suspicious, I would investigate:

- Which service started?
- Was the service expected?
- Did the service spawn unusual processes?
- Were files downloaded?
- Were registry modifications made?

---

## Conclusion

This event represents normal Windows service authentication.

No escalation is recommended based solely on this event.
