# LLM-DFIR | Forensic Triage Report

> Automated preliminary triage. **Not a forensic certification or determination of compromise.**

## Evidence manifest

- Source file: `case_002_authentication_review.json`
- SHA-256 of exact source bytes: `409ae2c066825fb47de095a0eab8b81bda629e3190357dc9bb8b0431e3fe4d45`
- Source size: 3252 bytes
- Parsed records: 5
- Timestamps not verified as UTC: 0

## Review candidates

These event-ID indicators are **not proof of an attack**. Candidate ATT&CK mappings require independent corroboration.

| Evidence ID | Timestamp | Host | Event ID | Observation | Severity | ATT&CK candidate |
|---|---|---|---|---|---|---|
| EV-00001 | 2026-11-13T14:00:00Z | WIN11-DFIR-LAB | 4625 | Failed logon | medium | T1110 (candidate; correlation required) |
| EV-00002 | 2026-11-13T14:00:45Z | WIN11-DFIR-LAB | 4625 | Failed logon | medium | T1110 (candidate; correlation required) |
| EV-00003 | 2026-11-13T14:01:30Z | WIN11-DFIR-LAB | 4625 | Failed logon | medium | T1110 (candidate; correlation required) |
| EV-00004 | 2026-11-13T14:02:00Z | WIN11-DFIR-LAB | 4625 | Failed logon | medium | T1110 (candidate; correlation required) |
| EV-00005 | 2026-11-13T14:04:00Z | WIN11-DFIR-LAB | 4624 | Successful logon | info | Not mapped without additional context |

## Event sequence candidates

- **Failed → successful logon** — `EV-00004` → `EV-00005` within 2.0 min on `WIN11-DFIR-LAB`. Review logon types, source addresses and authentication context; sequence alone is not proof of compromise.

## Analyst notes (unverified)

SYNTHETIC TRAINING DATA ONLY. Generated event leads require independent validation; no real intrusion or unauthorized action is asserted.

## Recommended validation

1. Confirm log collection coverage, source authenticity, and timestamp context.
2. Correlate Windows logon IDs, host processes, account changes, and change records.
3. Review each ATT&CK candidate manually; do not infer malicious intent from a single event ID.
4. Preserve originals, record handling procedures, and document analyst decisions.

## Limitations

This educational prototype is not an EVTX parser, SIEM replacement, full chain-of-custody system, or validated forensic expert system. Unparsed or naive timestamps may not sort chronologically. AI text, if generated separately, is advisory and is not incorporated as verified evidence.
