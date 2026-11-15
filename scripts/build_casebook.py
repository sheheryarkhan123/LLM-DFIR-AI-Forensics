"""Regenerate all deterministic casebook reports; makes no network calls."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.core import analyze, report_markdown  # noqa: E402

CASES = {
    "case_001_account_group_change.json": "case_001_report.md",
    "case_002_authentication_review.json": "case_002_report.md",
}


def main():
    out = ROOT / "cases" / "generated"
    out.mkdir(parents=True, exist_ok=True)
    for fixture, name in CASES.items():
        payload = (ROOT / "samples" / fixture).read_bytes()
        result = analyze(payload, fixture)
        notes = ("SYNTHETIC TRAINING DATA ONLY. Generated event leads require "
                 "independent validation; no real intrusion or unauthorized action is asserted.")
        (out / name).write_text(report_markdown(result, notes), encoding="utf-8")
        print(f"{name}: {result['count']} events, {len(result['sequences'])} lead(s), SHA-256 {result['sha256'][:12]}…")


if __name__ == "__main__":
    main()
