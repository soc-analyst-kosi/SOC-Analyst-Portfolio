# Splunk Correlation Detection

## Objective
Correlate multiple Windows security events to identify possible account compromise activity.

---

## Events Correlated
- Event ID 4625 – Failed Login
- Event ID 4624 – Successful Login
- Event ID 4688 – Process Execution

---

## SPL Query

```spl
index=* (EventCode=4625 OR EventCode=4624 OR EventCode=4688)
| eval stage=case(
    EventCode==4625, "1-Failed Login",
    EventCode==4624, "2-Successful Login",
    EventCode==4688, "3-Process Execution"
)
| stats values(stage) as attack_chain by Account_Name
| where mvcount(attack_chain) >= 2
```

---

## Alternative Correlation Query

```spl
index=* (EventCode=4625 OR EventCode=4624 OR EventCode=4688)
| eval EventType=case(
    EventCode==4625,"Failed Login",
    EventCode==4624,"Successful Login",
    EventCode==4688,"Process Execution"
)
| stats values(EventType) as Activities by Account_Name
| where mvcount(Activities) >= 2
```

---

## Investigation Summary
Security events were correlated to identify suspicious login behavior followed by command execution activity.

---

## Analysis
The observed sequence may indicate unauthorized access followed by reconnaissance activity.

---

## Skills Demonstrated
- Event Correlation
- Threat Detection
- Detection Engineering
- Security Analysis

---

## Screenshots
Stored in the screenshots folder.
