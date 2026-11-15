# Changelog

## 1.2 — Reproducible Wazuh investigation casebook

- Added two fully synthetic, documented Windows 11/Wazuh case studies with source fixtures and reproducible reports.
- Added a casebook tab and selectable sample scenarios to the local-first UI.
- Corrected a Windows 4732 field-role pitfall: `targetUserName` is the group. Correlation with 4720 now requires an exact new-account SID ↔ added-member SID match.
- Improved failed→successful logon review with source-IP consistency checks where source addresses are present.
- Documented a safe workflow for collecting, validating and privately reviewing real lab alerts.
- Added regression tests for event-field roles and casebook fixtures.


## 1.1 — Modern investigation workspace

- Redesigned Streamlit dashboard with a modern dark theme and four purpose-based tabs.
- Added demo-first experience, evidence filters, severity overview and case export panel.
- Added deterministic sequence leads (4625→4624 and 4720→4732) with same host/user and 30-minute constraints.
- Improved UTC-aware timeline normalization and warnings for unverified timestamps.
- Added cloud transfer authorization checkbox and detailed security documentation.
- Added a GitHub Actions test workflow and expanded automated tests.

## 1.0 — Initial educational prototype

- Structured JSON/JSONL/CSV parsing, SHA-256, event-ID heuristics, timeline and Markdown report.
- Optional Ollama and OpenAI API notes.
