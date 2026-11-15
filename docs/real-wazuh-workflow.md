# Replacing demonstrations with real, authorized Wazuh evidence

**The GitHub casebook intentionally contains no real screenshots, personal logs, API keys, or client data.** This guide explains how to perform the same workflow on your own Windows 11 + Ubuntu Wazuh lab without mislabeling fictional data as observed results.

## Prerequisites

- Ubuntu VM running the Wazuh manager and dashboard; Windows 11 VM with an active agent.
- Both hosts in a private / lab network and under your control.
- Windows auditing configured for the security events of interest. The presence of an event in Windows **does not guarantee** a Wazuh alert: collection, rules and thresholds matter.
- Record Wazuh version, agent version, Windows build, VM network settings and UTC offset in local analyst notes.

## Practical capture (inside your lab)

1. In Wazuh, verify the Windows agent is active and that the **timestamp, agent name, event ID, and Windows event data** are visible for the desired alerts.
2. Trigger only authorized, reversible tests inside the isolated Windows 11 VM, and identify their event IDs using Windows Event Viewer as an independent source.
3. In a safe working location, **export or copy a narrow set of JSON alerts** corresponding to your VM and test interval. The manager's alert stream is commonly stored at `/var/ossec/logs/alerts/alerts.json`, but that file may contain sensitive events from *all* managed endpoints. Do **not** copy the full stream into GitHub.
4. Store raw originals in a private, access-controlled location; record original SHA-256, acquisition time, collector and how the working copy was produced. Hashing does not establish chain of custody by itself.
5. Open the Streamlit application, choose **Upload evidence**, and import an authorized JSON/JSONL/CSV working copy. Check the evidence IDs and normalized event fields; compare against the original logs.
6. Examine candidate sequences carefully. In particular, event **4732** has **group** name in `TargetUserName`, whereas the new member is identified using `MemberSid`; the code only pairs it to 4720 when the created-account SID matches.
7. Export the Markdown report locally. Add an analyst-reviewed conclusion and relevant supporting screenshots in a **private** case folder.
8. For public GitHub, publish only synthetic reproductions or thoroughly reviewed, authorized sanitizations. Removing usernames and IPs may be insufficient because timestamps, file names, SIDs, host IDs and free-text fields can also disclose details.

### Example: read a small part of the manager's JSON stream **privately**

```bash
# Run only on a Wazuh manager you administer.
# Prints 10 recent alert records to your terminal: review content before copying.
sudo tail -n 10 /var/ossec/logs/alerts/alerts.json
```

The Streamlit application accepts a JSON array or newline-delimited JSON file. This example is for local triage only: avoid command-line exports containing private case data in shared directories. **Wazuh alert logs are not a complete forensic event stream** and should not be presented as complete evidence coverage.

## Evidence needed to make these GitHub case studies *real*

- A timestamped Wazuh alert export or sanitized screenshots from your *actual Windows 11 agent*.
- The exact test actions you performed in the lab, with dates/timezone.
- Event Viewer confirmation, agent name and version, and screenshot captions.
- Analyst decisions and false-positive explanations.

**Never** state “real incident confirmed” simply because a rule triggered or an LLM suggested a technique.
