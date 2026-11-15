# LLM-DFIR | Investigation casebook

All casebook datasets are **fully synthetic**, intentionally fictional, and suitable for public GitHub demonstration. They are **not exports of the author’s actual Wazuh installation**. They reflect the same Windows event families commonly collected by a Windows 11 Wazuh agent. Real evidence should never be claimed until a real, authorized working copy has been analyzed and verified.

| Case | Scenario | Wazuh-style events | What it illustrates |
|---|---|---|---|
| [CASE-001](CASE-001-account-group-change.md) | New account followed by local group membership | 4720, 4732, 4624, 4698 | Match 4720 created-account SID to 4732 member SID; review privileges and follow-on actions |
| [CASE-002](CASE-002-authentication-review.md) | Several failed logons and later success | 4625, 4624 | Review failed→success leads without automatically claiming brute force |

**Workflow:** Pick a case in the dashboard sidebar, open **Evidence explorer**, view **Sequence leads**, and export a draft report. To regenerate deterministic reports, run `python scripts/build_casebook.py`.

The synthetic `192.0.2.0/24` and `198.51.100.0/24` addresses come from documentation-only address blocks. The fictional user accounts, hostnames, event record IDs and SIDs do not represent real persons or systems.
