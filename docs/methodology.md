# Triage methodology

## Processing pipeline

1. **Preserve** original evidence outside this application; use an authorized working copy.
2. **Calculate SHA-256** from exact uploaded bytes. This establishes a digest, **not** chain of custody or authenticity by itself.
3. **Parse** UTF-8 JSON, JSONL/NDJSON or CSV; enforce 15 MB and 50,000-record limits.
4. **Normalize** event IDs, source evidence IDs, host, user, description and timezone-aware timestamps.
5. **Mark review candidates** through transparent rules. Every event ID is context-sensitive.
6. **Correlate conservative sequences** within 30 minutes using timezone-aware timestamps: for 4625→4624, host/account with no conflicting source IP; for 4720→4732, the exact created-account SID and added-member SID on the same host. Windows 4732 `TargetUserName` is the group, **not the member**.
7. **Generate human-readable reports** distinguishing deterministic evidence from analyst notes.
8. **Optionally request LLM hypotheses**, then corroborate every statement against source events and other artifacts.

## Event ordering

Timezone-aware ISO 8601 and numeric Unix timestamps are normalized to UTC for chronological ordering. Values without an explicit offset are kept in their original form and marked unverified. Do not rely on ordering of unverified timestamps.

## AI limitations

Only selected normalized fields from up to 40 events reach the model. Prompt injection may still occur in log data; protective instructions do not guarantee safety. Model outputs are **never accepted automatically as forensic conclusions**. Do not treat ATT&CK mappings or a suggested sequence as an established attack chain.

## Validation goals (not yet benchmarked)

Future empirical evaluation should report parsing accuracy, event recall, lead precision, false positives, citation accuracy, hallucination rate, and analyst review time on labelled, non-sensitive datasets. No such performance claims are made in version 1.2.
