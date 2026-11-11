
# BL-003 — Suspicious PowerShell Execution

**Organization:** Bayline Logistics (Fictional)  
**Incident Type:** Suspicious script execution / suspected endpoint compromise  
**Severity:** High  
**Disposition:** Suspected compromise  
**Status:** Immediate Tier 2 escalation recommended  
**Analyst:** SOC Tier 1  
**Evidence Window:** 2026-11-10 14:18–14:20 UTC

---

## 1. Alert Summary

EDR recorded PowerShell execution following the opening of an invoice attachment on Dana's workstation, FIN-09.

An extracted shortcut triggered hidden PowerShell execution from a user-writable temporary directory.

A related PowerShell script-block event recorded system information collection.

The same process was associated with an allowed outbound HTTP POST to the sender's domain.

No prevention action was recorded for the EDR alert.

## 2. Affected Assets

- User: dana
- Host: FIN-09
- Source IP: 10.30.0.19
- Process: powershell.exe
- Process ID: 6220
- Parent process: explorer.exe
- Trigger file: Invoice.lnk
- Script: invoice-check.ps1
- Destination: invoice-help.example

## 3. Evidence Timeline

| Time (UTC) | Record | Observation |
|---|---|---|
| 14:18:00 | P06 | Invoice.zip opened; Invoice.lnk extracted |
| 14:19:00 | P07 | Hidden PowerShell launched, PID 6220 |
| 14:19:01 | P08 | Script block Get-ComputerInfo logged |
| 14:19:04 | P09 | Allowed POST to invoice-help.example |
| 14:20:00 | P10 | EDR detection; prevention_action=none |

Dana reported the attachment interaction at 14:25 UTC.

## 4. Confirmed Observations

### File Activity

P06 records Invoice.zip opened on FIN-09.

The event identifies Invoice.lnk as an extracted file.

The origin_message field connects the file to email M202.

### Process Activity

P07 records PowerShell process 6220 launched through the Invoice.lnk trigger.

The command includes:

`-NoProfile -WindowStyle Hidden`

The script was located at:

`C:\Users\dana\AppData\Local\Temp\invoice-check.ps1`

### PowerShell Logging

P08 records:

`Get-ComputerInfo`

The process ID matches P07.

### Network Activity

P09 records:

- Destination: invoice-help.example
- Method: POST
- Status: 200
- Outbound bytes: 2048
- Initiating process ID: 6220

### EDR Alert

P10 records:

`Unusual PowerShell from user-writable location`

It also records:

`prevention_action=none`

No prevention action is demonstrated for the alert.

## 5. User Statement

Dana reports opening an invoice attachment and observing a brief window.

She denies intentionally initiating administration or diagnostic activity.

The statement is consistent with unexpected execution but is not independent proof of malicious intent.

## 6. Analyst Assessment

The sequence strongly suggests potentially harmful execution initiated by a suspicious email attachment.

Significant indicators include:

- Unsolicited invoice attachment.
- Extracted shortcut used as a trigger.
- PowerShell launched through explorer.exe.
- Hidden execution window.
- Script stored in a user-writable temporary directory.
- System-information collection command.
- Associated outbound POST to the sender's domain.
- Absence of a matching approved change for FIN-09.

The combination is substantially more suspicious than the Get-ComputerInfo command alone.

### Data Disclosure Assessment

The POST confirms outbound communication metadata.

The provided records do not identify the transmitted payload.

Therefore, sensitive-data exfiltration is suspected as a possibility, not confirmed.

## 7. Alternative Explanations

A legitimate diagnostic script could use Get-ComputerInfo.

However, a legitimate explanation would need to account for the invoice shortcut, hidden execution, unapproved script path, and outbound communication.

No such authorization has been provided.

The verified CHG-209 change applies to OPS-12, not FIN-09.

## 8. Unknowns

- Full contents of invoice-check.ps1.
- Additional script blocks or subprocesses.
- Whether the shortcut launched other commands.
- Exact outbound payload contents.
- Whether data was stored by the remote system.
- Additional network connections after the supplied sample.
- Whether the process remained active.
- Persistence or lateral movement.
- Other affected accounts or endpoints.

## 9. Severity Rationale

High: Likely harmful execution supported by correlated file, process, script, network, and EDR events.

The provided evidence supports suspected compromise without establishing confirmed malware identity or data theft.

## 10. Actions Completed

- Correlated P06–P10.
- Verified matching process identifier 6220.
- Linked the process to email M202 through the attachment evidence.
- Documented suspicious execution context.
- Compared the activity with approved CHG-209 administration.
- Prepared escalation recommendation.

No isolation, blocking, account disabling, or remediation was performed.

## 11. Requested Actions

Tier 2 should immediately:

1. Assess and authorize containment of FIN-09 as appropriate.
2. Preserve relevant endpoint and process evidence.
3. Obtain Invoice.zip, Invoice.lnk, and invoice-check.ps1 for analysis.
4. Retrieve complete EDR process-tree telemetry.
5. Review PowerShell script-block and related execution logs.
6. Examine HTTP POST metadata and available payload records.
7. Obtain full network telemetry beyond 14:21 UTC.
8. Search for matching indicators on other endpoints.
9. Coordinate email remediation with ticket BL-001.
10. Determine whether identity compromise or data disclosure occurred.

## 12. Escalation and Closure

**Escalation Owner:** Tier 2 / Incident Response

**Escalation Reason:** Evidence of suspicious attachment-triggered execution and associated outbound communication without confirmed prevention.

**Closure Criteria:** Complete containment assessment, establish execution and communication scope, analyze recovered artifacts, document remediation, and validate recovery or an evidence-supported benign conclusion.

**Status:** Escalation recommended; investigation unresolved.

---

**Simulation Notice:** This is an educational incident ticket based on synthetic evidence.
