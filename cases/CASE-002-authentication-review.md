# CASE-002 | Authentication anomalies and follow-on success

> **Dataset status: SYNTHETIC EXERCISE — NOT REAL EVIDENCE**  
> **Decision status: Investigative lead; no brute-force conclusion established.**

## Scenario

A fictional Windows endpoint records repeated failed network logons from one documentation-only source IP, across two test accounts, followed by a successful logon for one account.

## Observed records (from synthetic JSON)

| UTC time | Evidence ID | Windows event | Observation |
|---|---|---|---|
| 14:00:00 | EV-00001 | 4625 | `lab-user` failed logon, documentation IP `198.51.100.42` |
| 14:00:45 | EV-00002 | 4625 | `lab-user` failed logon, same source |
| 14:01:30 | EV-00003 | 4625 | `analyst-test` failed logon, same source |
| 14:02:00 | EV-00004 | 4625 | `lab-user` failed logon, same source |
| 14:04:00 | EV-00005 | 4624 | `lab-user` successful logon, same source |

The deterministic parser generates a single **failed→successful** review lead based on the most recent matching failed attempt and successful logon; it does **not** independently identify a password-spray attack.

## Analyst questions

- Were the failed attempts expected, such as a misconfigured service or test account?
- Were the logon types, source addresses, host and target accounts consistent?
- Is the source IP shared through NAT, a VPN or a proxy?
- Do authentication ticket, process and endpoint records support a broader incident?
- Does the environment's normal authentication baseline justify escalation?

## Assessment and next steps

**Open / inconclusive.** Confirm context with system owners and collect additional logon events or telemetry before asserting brute force, credential compromise or lateral movement.

## Inputs and reproducibility

- Fixture: [`samples/case_002_authentication_review.json`](../samples/case_002_authentication_review.json)
- Deterministic generated report: [`cases/generated/case_002_report.md`](generated/case_002_report.md)
- Regenerate: `python scripts/build_casebook.py`
