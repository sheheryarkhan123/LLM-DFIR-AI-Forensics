# Contributing

Contributions should improve reproducibility, analyst transparency and safe-by-default handling. Before proposing a change:

1. Use synthetic, fictional fixtures only. Never commit real client data, API keys or internal host details.
2. Describe what an event actually establishes, separating observations from hypotheses.
3. Add or update deterministic tests for parsing, timestamp handling and candidate mappings.
4. Run `python -m unittest discover -s tests -v` and `python -m compileall -q app`.
5. Explain how the change affects privacy, evidence handling and false-positive risks.

This is an educational prototype. Do not present unverified model narratives as expert findings.
