# Threat Hunting

## Objective
Perform proactive threat hunting to identify suspicious command execution activity after successful logins.

---

## Events Investigated
- Event ID 4624 – Successful Login
- Event ID 4688 – Process Creation

---

## SPL Query

```spl
index=* EventCode=4688
| search Process_Name="*whoami*" OR Process_Name="*powershell*" OR Process_Name="*cmd*"
| table _time, Account_Name, Process_Name, CommandLine
```

---

## Advanced Hunting Query

```spl
index=* (EventCode=4624 OR EventCode=4688)
| stats values(EventCode) as Events values(Process_Name) as Processes by Account_Name
| where mvcount(Events) >= 2
```

---

## Investigation Summary
Threat hunting activities were performed to identify suspicious command execution commonly associated with reconnaissance behavior.

---

## Findings
Processes such as whoami.exe and cmd.exe were identified after successful login activity.

---

## Skills Demonstrated
- Threat Hunting
- Behavioral Analysis
- Reconnaissance Detection
- SIEM Investigation

---

## Screenshots
Stored in the screenshots folder.
