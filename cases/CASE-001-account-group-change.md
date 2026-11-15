# CASE-001 | Account creation and local-group membership review

> **Dataset status: SYNTHETIC EXERCISE — NOT REAL EVIDENCE**  
> **Decision status: Investigative lead; no compromise established.**

## Scenario

In a fictional Windows 11 training VM, an account appears in event **4720**, followed two minutes later by event **4732** showing a new member of the local **Administrators** group. Later **4624** and **4698** events create additional questions about how the account was used.

## Observed records (from synthetic JSON)

| UTC time | Evidence ID | Windows event | Source observation |
|---|---|---|---|
| 09:20 | EV-00001 | 4720 | Account `training-auditor` created; new account SID recorded |
| 09:22 | EV-00002 | 4732 | Member SID equals the 4720 created-account SID; target group is `Administrators` |
| 09:28 | EV-00003 | 4624 | Successful network logon for `training-auditor` from documentation IP `192.0.2.25` |
| 09:33 | EV-00004 | 4698 | Scheduled-task creation event with subject `training-auditor` |

Note: In Windows event **4732**, `targetUserName` names the *group*, whereas `memberSid` identifies the added *member*. Pairing 4720 and 4732 by `targetUserName` would be incorrect; the detection requires an explicit SID match. Microsoft's 4732 field definitions are referenced in [`docs/references.md`](../docs/references.md).

## Hypotheses to examine — not established findings

- A legitimate lab administrator may have provisioned and tested a temporary account.
- An unexpected privileged account could indicate misuse if it was not authorized.
- A scheduled task could be routine maintenance or a persistence mechanism; the event ID alone cannot distinguish the two.

## Validation checklist

- [ ] Confirm the account creation and membership change against an approved request.
- [ ] Validate **exact created-account SID ↔ added-member SID** and the Windows host.
- [ ] Check subject user, subject logon ID and underlying Windows security audit record.
- [ ] Review the logon type, source IP and associated authentication details.
- [ ] Retrieve task path, arguments, owner and execution history before assessing event 4698.
- [ ] Reconcile event timestamps, agent time and possible Wazuh collection delays.
- [ ] Record analyst conclusion as *authorized*, *unexplained* or *requires escalation* only after verification.

## Analyst assessment

**Open / inconclusive.** The synthetic event chain demonstrates correlation logic, not an actual intrusion. No conclusion is made about attacker intent or malicious behavior.

## Inputs and reproducibility

- Fixture: [`samples/case_001_account_group_change.json`](../samples/case_001_account_group_change.json)
- Deterministic generated report: [`cases/generated/case_001_report.md`](generated/case_001_report.md)
- Regenerate: `python scripts/build_casebook.py`
