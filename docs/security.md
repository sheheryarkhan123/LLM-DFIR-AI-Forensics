# Security and data-handling notes

- **Source logs are untrusted.** Treat filenames, descriptions and event fields as potentially hostile input.
- **Do not publish case evidence.** Only fictional, synthetic events belong in this repository.
- **No automatic external requests.** The offline parser works without internet. AI requests happen only through an explicit UI action.
- **Cloud privacy.** Cloud mode sends selected summaries to `https://api.openai.com/v1/chat/completions`; the user must acknowledge authorization first. Hostnames, event IDs, and timestamps may still be sensitive.
- **Credentials.** Cloud keys are entered in a password field; do not share them in screenshots, shell commands, issue reports, or commits. This tool makes no claim of secure secret management in a shared or hostile Streamlit deployment.
- **Local deployment only.** This prototype has no login, role separation, audit-trail or multi-tenant isolation. Do not expose it publicly or deploy it on a shared internet-facing server.
- **Hashing.** A SHA-256 digest alone does not establish evidentiary integrity throughout acquisition, custody, and transport.
- **Prompt injection.** System instructions reduce risk but cannot guarantee resistance to instruction-like text embedded in logs.
- **Known limitation.** Plain JSON/CSV exports do not preserve every forensic characteristic of native Windows EVTX files.

For a security issue, avoid public disclosure of credentials or private evidence. Open a minimal reproducible issue containing synthetic sample data only.
