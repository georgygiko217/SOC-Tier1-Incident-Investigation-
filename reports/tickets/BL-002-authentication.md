
# BL-002 — Suspicious Authentication Activity

**Organization:** Bayline Logistics (Fictional)  
**Incident Type:** Authentication anomaly  
**Severity:** Medium (provisional)  
**Disposition:** Inconclusive  
**Status:** Open — verification required  
**Analyst:** SOC Tier 1  
**Evidence Window:** 2026-11-10 14:02–14:07 UTC

---

## 1. Alert Summary

Three failed network authentication attempts against FS-02 were followed by one successful logon.

The activity involved Leo's account and originated from his assigned workstation, OPS-12.

## 2. Affected Assets

- Account: leo
- Source host: OPS-12
- Source IP: 10.30.0.21
- Target host: FS-02
- Logon type: 3 (network logon)
- Successful session identifier: 0xB22

## 3. Evidence Timeline

| Time (UTC) | Record | Event |
|---|---|---|
| 14:02:00 | P02 | Event 4625 — bad password |
| 14:03:00 | P03 | Event 4625 — bad password |
| 14:04:00 | P04 | Event 4625 — bad password |
| 14:07:00 | P05 | Event 4624 — successful logon |

## 4. Confirmed Observations

- Three failed authentication events occurred.
- All failures recorded reason=bad_password.
- The source was Leo's assigned workstation.
- The target was FS-02.
- A subsequent successful network logon occurred.
- The successful event recorded logon_id=0xB22.

## 5. User Statement

Leo reported:

- Changing his password at 13:50 UTC.
- Leaving an old mapped drive connected.
- Reconnecting that drive at 14:07 UTC.

This statement has not been independently verified.

## 6. Analyst Assessment

The event pattern is consistent with a mapped drive repeatedly attempting to authenticate using outdated credentials.

The later successful logon is consistent with the reported reconnection.

However, the evidence does not establish which process initiated the activity or what resources the successful session accessed.

Unauthorized access has not been demonstrated.

## 7. Alternative Explanations

Potential explanations include:

1. Stale mapped-drive credentials.
2. Another application using outdated credentials.
3. Unauthorized credential use from Leo's workstation.

The first explanation is supported by the assigned source and the user statement, but additional logs are needed.

## 8. Unknowns

- Independent proof of the password change.
- Initiating process for the authentication requests.
- Mapped-drive connection history.
- Files accessed during session 0xB22.
- Additional authentication activity outside the sample.

## 9. Severity Rationale

Medium (provisional) pending verification.

The supplied evidence does not establish a malicious attempt, so the disposition is inconclusive rather than malicious.

If authorized activity is confirmed, reclassify as Low and close.

If unauthorized successful access is demonstrated, escalate to High.

## 10. Actions Completed

- Reviewed P02–P05.
- Correlated source, account, target, and logon type.
- Compared events with Leo's explanation.
- Documented alternative hypotheses.

No account changes or session termination were performed.

## 11. Requested Evidence

### Password-Change Audit

Confirm whether Leo changed his password at approximately 13:50.

### OPS-12 Process and Mapped-Drive Logs

Determine whether the attempts originated from a mapped-drive connection or another process.

### FS-02 Session and File-Access Logs

Investigate successful session 0xB22 and identify any resources accessed.

### Expanded Authentication History

Determine whether similar failures or unexpected logons occurred outside the provided window.

## 12. Escalation and Closure

**Escalation Owner:** Tier 2 / Identity Security if the activity cannot be verified or suspicious evidence emerges.

**Current Action:** Gather corroborating evidence.

**Closure Criteria:** Independently verify authorized activity and review session access, or escalate if evidence of unauthorized access emerges.

---

**Simulation Notice:** This is an educational incident ticket based on synthetic evidence.
