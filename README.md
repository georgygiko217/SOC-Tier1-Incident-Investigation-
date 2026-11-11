# SOC-Tier1-Incident-Investigation-
Simulated SOC Tier 1 investigation covering phishing, Windows authentication, PowerShell detection, log correlation and incident response.

# SOC Tier 1 — Security Incident Investigation

## Project Overview

This project demonstrates a simulated Security Operations Center (SOC) Tier 1 investigation involving three security alerts at Bayline Logistics, a fictional organization.

The investigation focuses on:
- Phishing email analysis
- Windows authentication failures and successful logons
- Suspicious PowerShell execution
- Endpoint Detection and Response (EDR) alerts
- Network traffic analysis
- Event correlation and incident escalation

**Disclaimer:** All events, users, hosts, and network addresses are synthetic. This project represents an educational investigation, not a real security incident.

## Tools and Technologies

- Windows PowerShell
- Windows Security Event Logs (4624 and 4625)
- PowerShell Script Block Logging (4104)
- Endpoint Detection and Response (EDR) telemetry
- Proxy and network logs
- CSV log analysis
- MITRE ATT&CK for investigation context

## Investigation Objectives

1. Analyze 12 synthetic security events.
2. Create chronological event timelines.
3. Identify suspicious authentication patterns.
4. Investigate potentially malicious PowerShell activity.
5. Correlate alerts using common event identifiers.
6. Distinguish confirmed facts from assumptions.
7. Assign incident severity and disposition.
8. Document findings and escalation recommendations.

## Environment

| Asset | Description |
|---|---|
| FIN-09 | Dana's finance workstation |
| OPS-12 | Leo's assigned workstation |
| FS-02 | File server |
| MGMT-02 | Approved administration server |
| 10.30.0.21 | Leo's workstation IP |
| 10.30.0.19 | Dana's workstation IP |
| 10.30.0.5 | Approved management source |
| svc_ops | Authorized administration account |

All timestamps are UTC.

## Investigation 1 — Suspicious Phishing Email

**Relevant Events:** P01, P06

An email was delivered to Dana from billing@invoice-help.example.

The message contained an attachment named Invoice.zip.

SPF, DKIM, and DMARC authentication checks passed.

However, successful email authentication does not establish that an email is legitimate or its attachments are safe.

EDR subsequently recorded the opening of Invoice.zip and the extraction of Invoice.lnk.

Both events were linked using message identifier M202.

### Findings

- Suspicious invoice attachment delivered.
- Sender domain had no known business relationship.
- Attachment activity linked to the delivered email.
- Subsequent suspicious execution identified.

**Severity:** Medium (individual email alert)

**Disposition:** Suspected malicious attempt

**Recommendation:** Escalate for recipient scoping, attachment analysis, and authorized remediation.

The related PowerShell execution is investigated separately under Incident 3.

## Investigation 2 — Suspicious Authentication Activity

**Relevant Events:** P02–P05

Windows Security logs recorded three unsuccessful network logon attempts against FS-02.

All originated from Leo's assigned workstation, 10.30.0.21.

The failed attempts were followed by a successful network logon.

| Time (UTC) | Event ID | Result |
|---|---|---|
| 14:02 | 4625 | Failed authentication |
| 14:03 | 4625 | Failed authentication |
| 14:04 | 4625 | Failed authentication |
| 14:07 | 4624 | Successful authentication |

Leo reported changing his password at 13:50 and reconnecting an old mapped drive at 14:07.

### Findings

- Failed and successful logons share the same user, source, destination, and network logon type.
- The source was Leo's assigned workstation.
- The sequence is consistent with outdated mapped-drive credentials.
- The user's explanation has not been independently verified.
- No unauthorized file access is demonstrated in the provided records.

**Severity:** Medium (provisional)

**Disposition:** Inconclusive

**Recommendation:** Verify the password-change event, mapped-drive activity, and file-access logs before closing.

## Investigation 3 — Suspicious PowerShell Execution

**Relevant Events:** P06–P10

EDR recorded Invoice.lnk triggering PowerShell execution on Dana's workstation.

The PowerShell process executed a script from a user-writable temporary directory.

### Process Details

- User: dana
- Host: FIN-09
- Parent process: explorer.exe
- Executable: powershell.exe
- Process ID: 6220
- Trigger: Invoice.lnk
- Script: invoice-check.ps1
- Execution option: Hidden window

PowerShell Event 4104 recorded the command:

`Get-ComputerInfo`

The same process subsequently initiated an outbound HTTP POST request to invoice-help.example.

### Network Evidence

| Field | Value |
|---|---|
| Destination | invoice-help.example |
| Method | POST |
| Status | 200 |
| Outbound bytes | 2048 |
| Initiating PID | 6220 |

The POST establishes outbound communication, but the provided records do not identify the transmitted content.

An EDR alert recorded prevention_action=none. No prevention action is documented for the alert.

### Findings

- The invoice attachment triggered a script.
- PowerShell executed with a hidden window.
- The script was located in a user-writable directory.
- The script performed system-information collection.
- An associated outbound POST occurred.
- No matching approved change was provided for FIN-09.
- Data exfiltration is possible but not confirmed.

**Severity:** High

**Disposition:** Suspected compromise

**Recommendation:** Immediately escalate to Tier 2 for containment assessment, script analysis, investigation of network activity, and preservation of evidence.

## Authorized Activity Comparison

Events P11 and P12 recorded authorized PowerShell execution by svc_ops on OPS-12.

The execution matched approved change CHG-209.

Verification included:
- Approved service account
- Expected management source
- Expected destination
- Approved script
- Matching script hash
- Owner confirmation

**Severity:** Low

**Disposition:** Benign authorized activity

**Recommendation:** Close this individual activity as authorized.

CHG-209 does not authorize the separate execution on FIN-09.

## Incident Summary

| Incident | Severity | Disposition |
|---|---|---|
| Suspicious invoice email | Medium | Suspected malicious attempt |
| Leo's authentication activity | Medium (provisional) | Inconclusive |
| Dana's PowerShell execution | High | Suspected compromise |
| Approved svc_ops execution | Low | Benign authorized activity |

## Response Authority

Under the simulated SOC playbook, Tier 1 may investigate, document evidence, create tickets, and recommend escalation.

Tier 2 authorizes account disabling, session revocation, endpoint isolation, and blocking.

No live containment actions were performed in this project.

## Key Lessons Learned

1. Successful SPF, DKIM, and DMARC checks do not guarantee an email is safe.
2. Authentication failures followed by success require contextual investigation.
3. PowerShell commands must be evaluated in their execution context.
4. Process identifiers and message identifiers strengthen event correlation.
5. HTTP POST metadata alone cannot establish data exfiltration.
6. Approved change records apply only to their authorized scope.
7. SOC analysts must distinguish confirmed evidence, user statements, assessments, and unknowns.
8. Escalation decisions must follow documented severity rules.

## References

- Microsoft — Email Authentication in Microsoft 365:
  https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about

- Microsoft — Audit Logon Events:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events

- Microsoft PowerShell Team — PowerShell and the Blue Team:
  https://devblogs.microsoft.com/powershell/powershell-the-blue-team/

## Portfolio Summary

Simulated a SOC Tier 1 investigation using Windows authentication logs, EDR telemetry, PowerShell script-block logs, and proxy records. Correlated security events, assessed suspicious activity, distinguished benign activity from suspected compromise, and documented evidence-based escalation recommendations.
