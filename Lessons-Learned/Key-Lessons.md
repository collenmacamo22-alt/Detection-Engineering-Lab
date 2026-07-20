# Key Lessons Learned

## Technical Lessons

- Individual Windows events should never be analyzed in isolation.
- Event correlation significantly improves detection accuracy.
- Parent-child process relationships provide valuable context during investigations.
- Legitimate Windows utilities such as PowerShell and certutil.exe can be abused by attackers.
- Detection rules should balance sensitivity with false-positive reduction.

---

## Detection Engineering Lessons

- Time windows improve detection quality.
- Severity should increase as additional indicators of compromise appear.
- Context is often more valuable than individual events.
- Detection logic should remain understandable and maintainable.
- Well-written detections support faster incident response.

---

## Personal Reflection

This project strengthened my understanding of Windows event correlation, attack chains, MITRE ATT&CK concepts, and the importance of building detections based on attacker behavior rather than isolated events.
