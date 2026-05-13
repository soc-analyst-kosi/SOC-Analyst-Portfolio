# Splunk Brute Force Detection

## Objective
Detect brute force login attempts using Splunk SIEM.

---

## Events Used
- Event ID 4625 – Failed Login
- Event ID 4624 – Successful Login

---

## SPL Query

```spl
index=* EventCode=4625
| bucket _time span=1m
| stats count by _time, Account_Name, Source_Network_Address
| where count >= 5
```

---

## Alert Query

```spl
index=* EventCode=4625
| stats count by Account_Name
| where count > 5
```

---

## Investigation Summary
Repeated failed login attempts were detected against a user account within a short timeframe.

---

## Findings
Possible brute force attack activity identified through failed login monitoring.

---

## Skills Demonstrated
- SPL Query Writing
- SIEM Monitoring
- Alert Creation
- Threat Detection

---

## Screenshots
Stored in the screenshots folder.
