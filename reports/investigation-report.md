
# SOC Tier 1 Investigation Report
## Bayline Logistics — Simulated Security Incident

**Investigation Date:** November 10, 2026  
**Organization:** Bayline Logistics (Fictional)  
**Analyst Role:** SOC Tier 1  
**Evidence:** 12 synthetic security records (P01–P12)  
**Time Zone:** UTC  
**Status:** Investigation completed using provided evidence; response recommendations pending authorization.

---

## 1. Executive Summary

This investigation examined 12 synthetic security events involving phishing, suspicious authentication, PowerShell execution, and authorized system administration.

Three security cases were identified:

1. A suspicious invoice email delivered to Dana, followed by attachment execution.
2. Multiple failed network logons for Leo, followed by successful authentication.
3. Suspicious PowerShell execution on Dana's workstation, associated with outbound network communication.

A fourth activity involving the approved service account `svc_ops` was reviewed as a benign comparison.

### Key Findings

- Dana's email and PowerShell events are strongly linked by message ID, attachment, process ID, host, and user.
- The suspicious PowerShell process initiated an allowed HTTP POST, but the transmitted content is unknown.
- Leo's authentication activity is consistent with his reported password-change and mapped-drive explanation, but independent verification is missing.
- The `svc_ops` execution matches approved change CHG-209 and is considered authorized.
- CHG-209 does not authorize activity on Dana's workstation FIN-09.

### Severity Summary

| Case | Severity | Disposition |
|---|---|---|
| BL-001 — Suspicious invoice email | Medium | Suspected malicious attempt |
| BL-002 — Leo authentication anomaly | Medium (provisional) | Inconclusive |
| BL-003 — Suspicious PowerShell execution | High | Suspected compromise |
| Authorized svc_ops comparison | Low | Benign authorized activity |

The PowerShell case warrants immediate escalation to Tier 2. No actual containment or remediation actions were performed.

---

## 2. Investigation Scope

### Environment

| Asset | Description |
|---|---|
| FIN-09 | Dana's finance workstation |
| OPS-12 | Leo's assigned workstation |
| FS-02 | File server |
| MGMT-02 | Approved administration server |
| 10.30.0.19 | FIN-09 workstation IP |
| 10.30.0.21 | OPS-12 workstation IP |
| 10.30.0.5 | Approved management source |
| svc_ops | Approved administration account |

### Evidence Limitations

The dataset contains only 12 selected records. It is not a complete endpoint, identity, or network history.

The supplied network sample ends at 14:21 UTC, while the change verification record is timestamped 14:22 UTC.

Absence of additional activity in the provided dataset does not establish absence of activity in the actual simulated environment.

User statements are treated as leads requiring independent corroboration.

---

## 3. Timeline — Dana

| Time (UTC) | Record | Observation |
|---|---|---|
| 14:00:00 | P01 | Invoice-themed email M202 delivered with Invoice.zip |
| 14:18:00 | P06 | Invoice.zip opened; Invoice.lnk extracted |
| 14:19:00 | P07 | Invoice.lnk triggers hidden PowerShell, PID 6220 |
| 14:19:01 | P08 | Event 4104 records Get-ComputerInfo for PID 6220 |
| 14:19:04 | P09 | PID 6220 associated with allowed HTTP POST |
| 14:20:00 | P10 | EDR alert; prevention_action=none |
| 14:25:00 | User statement | Dana reports opening attachment and seeing a brief window |

The sequence establishes a supported relationship between the email attachment, script execution, and outbound communication.

---

## 4. Timeline — Leo

| Time (UTC) | Record | Observation |
|---|---|---|
| 13:50:00 | User statement | Leo reports changing his password |
| 14:02:00 | P02 | Event 4625, bad-password network logon |
| 14:03:00 | P03 | Event 4625, bad-password network logon |
| 14:04:00 | P04 | Event 4625, bad-password network logon |
| 14:07:00 | P05 | Event 4624, successful network logon, ID 0xB22 |
| 14:07:00 | User statement | Leo reports reconnecting his mapped drive |

All four logged authentication events concern Leo, FS-02, source 10.30.0.21, and logon type 3.

The sequence is consistent with stale credentials but does not independently prove the explanation.

---

## 5. Finding A — Suspicious Email

### Observed Facts

P01 records delivery of an email from `billing@invoice-help.example` to Dana.

The subject is "Invoice overdue."

The attachment is `Invoice.zip`.

SPF, DKIM, and DMARC results are all recorded as pass.

The company has no known business relationship with the sender domain.

### User Statement

Dana reports opening the attachment.

### Assessment

The invoice email is suspicious and is linked to subsequent execution activity.

SPF, DKIM, and DMARC passing does not prove that an email is safe or that its sender is trustworthy.

SPF evaluates authorized sending infrastructure, DKIM evaluates a cryptographic message signature, and DMARC evaluates aligned authentication.

An attacker-controlled domain can have properly configured email authentication.

### Unknowns

- Whether the sender is an actual business.
- Whether the original attachment contains additional malicious files.
- Whether other users received the message.
- Whether the full email headers reveal other suspicious indicators.

### Decision

Severity: Medium for the individual email delivery alert.

Disposition: Suspected malicious attempt.

Escalate for tenant-wide message scoping and authorized remediation.

Related execution is assessed separately under BL-003.

---

## 6. Finding B — Authentication Activity

### Observed Facts

P02–P04 record three unsuccessful network logons with bad-password reasons.

P05 records a successful network logon.

The source address is 10.30.0.21, Leo's assigned workstation.

All events target FS-02 using account `leo`.

### User Statement

Leo reports changing his password at 13:50 and reconnecting a mapped drive at 14:07.

### Assessment

The pattern is consistent with an existing mapped drive attempting to authenticate using outdated credentials.

The success at 14:07 is consistent with Leo's reported reconnection.

However, a successful logon proves only that authentication succeeded, not who initiated it or whether the activity was authorized.

### Unknowns

- Whether the reported password change occurred.
- Which process initiated the connections.
- Whether the successful session accessed sensitive files.
- Whether additional failed attempts occurred outside the sample.

### Decision

Severity: Medium, provisional.

Disposition: Inconclusive.

Gather additional evidence before closure.

If the explanation is verified and no suspicious access occurred, reclassify as Low / benign authorized activity.

If successful unauthorized access is demonstrated, escalate as High.

---

## 7. Finding C — PowerShell Execution

### Observed Facts

P06 links the opened attachment to email M202.

P07 records PowerShell PID 6220 launched from explorer.exe through Invoice.lnk.

The command includes:

`-NoProfile -WindowStyle Hidden`

The script path is:

`C:\Users\dana\AppData\Local\Temp\invoice-check.ps1`

P08 records `Get-ComputerInfo` in a PowerShell script-block log associated with PID 6220.

P09 records an allowed POST to `invoice-help.example`, associated with PID 6220.

The proxy reports:

- HTTP method: POST
- Status: 200
- Outbound bytes: 2048

P10 records an EDR alert with `prevention_action=none`.

### User Statement

Dana confirms opening the attachment but denies intentionally starting administration or diagnostics.

### Assessment

This sequence is strongly suspicious because an invoice attachment triggered hidden PowerShell execution from a user-writable directory.

The associated network request adds concern about possible information disclosure.

`Get-ComputerInfo` is not inherently malicious. Its meaning depends on the surrounding activity and authorization.

The records do not establish which information, if any, was transferred.

### Unknowns

- Complete script contents and behavior.
- Whether additional commands executed.
- Whether persistence was established.
- Exact HTTP POST payload contents.
- Whether the remote destination received or retained sensitive data.
- Whether further network connections occurred after the sample.
- Whether the EDR process remained active.

### Decision

Severity: High.

Disposition: Suspected compromise.

Escalate immediately to Tier 2 for containment assessment, evidence preservation, script analysis, and broader network scoping.

Tier 1 does not independently authorize isolation, account disabling, or blocking.

---

## 8. Finding D — Authorized Administration

### Observed Facts

P11 records execution of `C:\Ops\inventory.ps1` on OPS-12 by `svc_ops`, originating from 10.30.0.5.

The parent process is `ManagementAgent.exe`.

P12 records verification of approved change CHG-209.

The script hash matches the approved script, and the owner confirms execution.

### Assessment

The observed activity matches the authorized account, source, target, script, and change window.

Disposition: Benign authorized activity.

Severity: Low.

Decision: Close this comparison activity as authorized.

CHG-209 does not authorize execution on FIN-09.

---

## 9. Event Correlation

| Records | Matching Evidence | Conclusion |
|---|---|---|
| P01, P06 | message_id=M202 / origin_message=M202 | Email-to-file association |
| P06, P07 | Invoice.lnk / trigger_file=Invoice.lnk | File-to-process association |
| P07, P08 | process_id=6220 | Process-to-script association |
| P07, P09 | process_id=6220 / initiating_process_id=6220 | Process-to-network association |
| P07, P10 | process_id=6220 | Execution-to-alert association |
| P02–P05 | User, source IP, target host, logon type | Related authentication sequence |
| P11, P12 | svc_ops, 10.30.0.5, OPS-12, expected script | Authorized change correlation |

No evidence establishes a common attack chain between Leo's authentication activity and Dana's suspicious execution.

Correlation was based on identifiers and event attributes, not timing alone.

---

## 10. Recommended Evidence Collection

| Requested Evidence | Purpose |
|---|---|
| Original email M202 and complete headers | Verify sender infrastructure and message authentication details |
| Invoice.zip and Invoice.lnk samples and hashes | Determine attachment behavior and indicators |
| Complete invoice-check.ps1 and script-block records | Determine executed commands and potential payloads |
| FIN-09 process tree and EDR telemetry | Identify further execution and persistence |
| Full proxy logs and available HTTP payload evidence | Investigate transmitted information and communication scope |
| FIN-09 network history after 14:21 | Identify subsequent communication |
| EDR response and device-state logs | Determine whether execution continued |
| Leo's password-change audit | Verify his explanation |
| OPS-12 mapped-drive and process records | Identify source of network authentication attempts |
| FS-02 file-access logs linked to 0xB22 | Determine activity during the authenticated session |
| Email recipient/message trace search | Identify other potentially affected users |
| Original CHG-209 approval records | Confirm scope of authorized administration |

---

## 11. Response Authority and Actions

Tier 1 is authorized to:

- Review and correlate available evidence.
- Create investigation tickets.
- Recommend severity and disposition.
- Request additional evidence.
- Escalate to Tier 2.

Tier 2 authorizes:

- Endpoint isolation.
- Account disabling.
- Session revocation.
- Network or domain blocking.

No live system changes were performed in this exercise.

All containment recommendations remain requests, not completed actions.

---

## 12. Final Conclusion

The most serious finding is Dana's suspicious attachment-triggered PowerShell execution and associated outbound network communication.

The evidence supports a High-severity suspected compromise and immediate Tier 2 escalation.

Leo's logon activity remains inconclusive pending corroboration of his mapped-drive explanation.

The approved svc_ops activity is independently verified as authorized and can be closed as benign.

The investigation demonstrates evidence-based triage, event correlation, recognition of uncertainty, severity assignment, and escalation within defined SOC Tier 1 authority.

---

## 13. References

1. Microsoft — Audit Logon Events  
   https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events

2. Microsoft PowerShell Team — PowerShell and the Blue Team  
   https://devblogs.microsoft.com/powershell/powershell-the-blue-team/

3. Microsoft — Email Authentication in Microsoft 365  
   https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about

**Disclaimer:** This report describes a fictional environment and synthetic security records. No actual systems were investigated or remediated.
