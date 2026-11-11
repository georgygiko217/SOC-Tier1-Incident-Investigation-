
# BL-001 — Suspicious Invoice Email

**Organization:** Bayline Logistics (Fictional)  
**Incident Type:** Suspected phishing / malicious attachment delivery  
**Severity:** Medium  
**Disposition:** Suspected malicious attempt  
**Status:** Escalation recommended; open  
**Analyst:** SOC Tier 1  
**Evidence Window:** 2026-11-10 14:00–14:18 UTC

---

## 1. Alert Summary

An invoice-themed email was delivered to Dana on FIN-09.

The message contained an attachment named Invoice.zip.

Subsequent EDR telemetry linked the attachment to an extracted shortcut file, Invoice.lnk, and later suspicious execution.

## 2. Affected Assets

- User: dana
- Host: FIN-09
- Sender: billing@invoice-help.example
- Message ID: M202
- Source IP recorded in email event: 198.51.100.30

## 3. Evidence Timeline

| Time (UTC) | Record | Event |
|---|---|---|
| 14:00:00 | P01 | Email M202 delivered |
| 14:18:00 | P06 | Invoice.zip opened; Invoice.lnk extracted |

At 14:25, Dana reported opening the attachment and seeing a brief window.

## 4. Confirmed Observations

- Email delivery was recorded.
- The email contained Invoice.zip.
- SPF, DKIM, and DMARC returned pass.
- An attachment event on FIN-09 references origin_message=M202.
- The company has no known relationship with the sender domain.

## 5. User Statement

Dana reports opening the attachment.

Her statement corroborates the general activity but does not establish the attachment's contents or intent.

## 6. Analyst Assessment

The invoice email is suspicious.

Passing email authentication results do not establish that the sender or attachment is safe.

The message is linked to subsequent suspicious execution through M202 and Invoice.lnk.

The associated execution is investigated separately in BL-003.

## 7. Alternative Explanations

A legitimate invoice workflow is possible in principle.

However, the unknown sender relationship, unexpected shortcut, and associated hidden PowerShell execution challenge that explanation.

A legitimate business purpose has not been verified.

## 8. Unknowns

- Sender identity and legitimacy.
- Complete attachment contents.
- Additional recipients.
- Whether other users opened the attachment.
- Whether additional messages used the same indicators.

## 9. Severity Rationale

Medium: Credible malicious attempt, evaluated as an individual delivery alert.

The associated execution meets the separate High-severity criteria documented in BL-003.

## 10. Actions Completed

- Reviewed P01 and P06.
- Correlated message identifier M202.
- Documented observed facts and uncertainty.
- Prepared escalation recommendation.

No email removal, blocking, or containment was performed.

## 11. Requested Actions

Tier 2 should:

- Search for other recipients of M202 or matching indicators.
- Analyze the attachment and extracted shortcut.
- Review the original email headers.
- Authorize removal or blocking if warranted.
- Coordinate investigation with BL-003.

## 12. Escalation and Closure

**Escalation Owner:** Tier 2 / Email Security

**Reason:** Suspicious attachment delivery associated with potentially harmful execution.

**Closure Criteria:** Complete message and recipient scoping, assess the attachment, perform authorized remediation, and document final disposition.

The ticket remains open pending those activities.

---

**Simulation Notice:** This is an educational incident ticket based on synthetic evidence.
