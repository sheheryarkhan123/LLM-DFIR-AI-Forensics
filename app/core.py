"""Deterministic forensic log triage. No network calls or AI dependencies."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone

MAX_UPLOAD_BYTES = 15 * 1024 * 1024
MAX_EVENTS = 50_000

# ATT&CK labels describe avenues to investigate, not identified attacks.
EVENTS = {
    "4625": ("Failed logon", "medium", "T1110 (candidate; correlation required)"),
    "4624": ("Successful logon", "info", "Not mapped without additional context"),
    "4720": ("User account created", "medium", "T1136 (candidate)"),
    "4732": ("Member added to local security group", "high", "T1098 (candidate)"),
    "4698": ("Scheduled task created", "medium", "T1053.005 (candidate)"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dig(obj, *paths):
    for path in paths:
        current = obj
        for key in path.split("."):
            if not isinstance(current, dict) or key not in current:
                current = None
                break
            current = current[key]
        if current is not None and current != "":
            return current
    return None


def parse_time(value) -> datetime | None:
    """Parse known ISO 8601/Unix epoch values for sorting without guessing other formats."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            # Reject ambiguous epoch milliseconds instead of silently guessing.
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None  # Naive timestamps have unknown timezone.
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def normalize(obj, index):
    """Build a compact event view, preserving distinctions in Windows event roles.

    For event 4732, targetUserName is the GROUP, not the member being added.
    Comparing it to a created account's targetUserName would invent a match.
    """
    if not isinstance(obj, dict):
        return None
    raw_event = dig(obj, "data.win.system.eventID", "win.system.eventID", "event_id", "EventID", "eventID", "EventCode")
    event_id = str(raw_event).strip() if raw_event is not None else ""
    raw_time = dig(obj, "data.win.system.systemTime", "win.system.systemTime", "timestamp", "@timestamp", "TimeCreated", "time")
    parsed_time = parse_time(raw_time)
    target_user = dig(obj, "data.win.eventdata.targetUserName", "win.eventdata.targetUserName", "target_user")
    subject_user = dig(obj, "data.win.eventdata.subjectUserName", "win.eventdata.subjectUserName", "subject_user")
    member_name = dig(obj, "data.win.eventdata.memberName", "win.eventdata.memberName", "member_name")
    member_sid = dig(obj, "data.win.eventdata.memberSid", "win.eventdata.memberSid", "member_sid")
    target_sid = dig(obj, "data.win.eventdata.targetSid", "win.eventdata.targetSid", "target_sid")
    source_ip = dig(obj, "data.win.eventdata.ipAddress", "win.eventdata.ipAddress", "source_ip", "src_ip")
    logon_type = dig(obj, "data.win.eventdata.logonType", "win.eventdata.logonType", "logon_type")
    record_id = dig(obj, "data.win.system.eventRecordID", "win.system.eventRecordID", "record_id")
    host = dig(obj, "agent.name", "data.win.system.computer", "win.system.computer", "host", "Computer")
    detail = dig(obj, "rule.description", "message", "Message")

    fallback_user = dig(obj, "user", "User")
    if event_id == "4732":
        # On Windows 4732, targetUserName identifies the GROUP, not the member.
        user = member_name if member_name not in (None, "-") else member_sid
    elif event_id == "4698":
        user = subject_user or fallback_user
    else:
        user = target_user or fallback_user or subject_user

    title, severity, technique = EVENTS.get(event_id, ("Unmapped event", "info", "Not mapped"))
    return {
        "evidence_id": f"EV-{index:05d}",
        "source_index": index,
        "record_id": str(record_id or "")[:100],
        "timestamp": parsed_time.isoformat().replace("+00:00", "Z") if parsed_time else str(raw_time or ""),
        "timestamp_verified_utc": parsed_time is not None,
        "event_id": event_id,
        "user": str(user or "")[:256],
        "host": str(host or "")[:256],
        "description": str(detail or title)[:1000],
        "finding": title,
        "severity": severity,
        "mitre_candidate": technique,
        "subject_user": str(subject_user or "")[:256],
        "target_user": str(target_user or "")[:256],
        "source_ip": str(source_ip or "")[:128],
        "logon_type": str(logon_type or "")[:32],
        "target_sid": str(target_sid or "")[:256] if event_id == "4720" else "",
        "member_sid": str(member_sid or "")[:256] if event_id == "4732" else "",
        "member_name": str(member_name or "")[:256] if event_id == "4732" else "",
        "group_name": str(target_user or "")[:256] if event_id == "4732" else "",
    }


def load_records(data: bytes, filename: str):
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Maximum upload size is 15 MB.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("The file must be UTF-8 encoded.") from exc
    ext = filename.lower().rsplit(".", 1)[-1]
    if ext == "csv":
        records = list(csv.DictReader(io.StringIO(text)))
    elif ext in {"jsonl", "ndjson"}:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    elif ext == "json":
        parsed = json.loads(text)
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict):
            records = next(
                (parsed[key] for key in ("alerts", "events", "records", "data") if isinstance(parsed.get(key), list)),
                [parsed],
            )
        else:
            raise ValueError("JSON root must be an object or array of objects.")
    else:
        raise ValueError("Supported formats: .json, .jsonl, .ndjson, .csv")
    if len(records) > MAX_EVENTS:
        raise ValueError(f"Maximum {MAX_EVENTS:,} events per upload.")
    return records


def correlate(events):
    """Flag cautious review leads from timezone-verified events (not attack claims).

    Logons: same host and target account; do not join conflicting source IPs.
    Account -> group: same host AND created-account SID equals added-member SID.
    """
    observed = []
    per_host = {}
    for event in events:
        when = parse_time(event["timestamp"])
        if when and event["host"]:
            per_host.setdefault(event["host"].casefold(), []).append((when, event))

    for group in per_host.values():
        group.sort(key=lambda item: item[0])
        failed_by_user = {}
        created_by_sid = {}
        for current_time, current in group:
            event_id = current["event_id"]
            if event_id == "4624" and current["user"]:
                username = current["user"].casefold()
                failure = failed_by_user.get(username)
                if failure:
                    first_time, first = failure
                    seconds = (current_time - first_time).total_seconds()
                    first_ip, last_ip = first["source_ip"], current["source_ip"]
                    if 0 <= seconds <= 1800 and (not first_ip or not last_ip or first_ip == last_ip):
                        observed.append({
                            "sequence": "Failed → successful logon",
                            "first_evidence_id": first["evidence_id"],
                            "second_evidence_id": current["evidence_id"],
                            "host": first["host"],
                            "user": current["user"],
                            "elapsed_minutes": round(seconds / 60, 1),
                            "review_note": "Review logon types, source addresses and authentication context; sequence alone is not proof of compromise.",
                        })
                        failed_by_user.pop(username, None)
            elif event_id == "4732" and current["member_sid"]:
                sid = current["member_sid"].casefold()
                precursor = created_by_sid.get(sid)
                if precursor:
                    first_time, first = precursor
                    seconds = (current_time - first_time).total_seconds()
                    if 0 <= seconds <= 1800:
                        group_name = current["group_name"] or "unspecified group"
                        observed.append({
                            "sequence": "Account creation → group membership (SID match)",
                            "first_evidence_id": first["evidence_id"],
                            "second_evidence_id": current["evidence_id"],
                            "host": first["host"],
                            "user": first["target_user"],
                            "elapsed_minutes": round(seconds / 60, 1),
                            "review_note": f"Exact member SID match; validate authorization for group '{group_name}'.",
                        })
                        created_by_sid.pop(sid, None)

            if event_id == "4625" and current["user"]:
                failed_by_user[current["user"].casefold()] = (current_time, current)
            elif event_id == "4720" and current["target_sid"]:
                created_by_sid[current["target_sid"].casefold()] = (current_time, current)

    return observed


def analyze(data: bytes, filename: str):
    records = load_records(data, filename)
    events = [normalize(record, i) for i, record in enumerate(records, 1)]
    events = [record for record in events if record is not None]
    # Unknown timezone strings come last; source evidence IDs retain original file order.
    events.sort(key=lambda e: (
        not e["timestamp_verified_utc"],
        e["timestamp"] if e["timestamp_verified_utc"] else "",
        e["evidence_id"],
    ))
    return {
        "sha256": sha256(data),
        "filename": filename,
        "byte_count": len(data),
        "count": len(events),
        "events": events,
        "sequences": correlate(events),
        "unverified_timestamps": sum(not e["timestamp_verified_utc"] for e in events),
    }


def report_markdown(result, analyst_notes=""):
    safe_name = str(result["filename"]).replace("`", "'").replace("\n", " ")
    lines = [
        "# LLM-DFIR | Forensic Triage Report", "",
        "> Automated preliminary triage. **Not a forensic certification or determination of compromise.**", "",
        "## Evidence manifest", "",
        f"- Source file: `{safe_name}`",
        f"- SHA-256 of exact source bytes: `{result['sha256']}`",
        f"- Source size: {result.get('byte_count', 'not recorded')} bytes",
        f"- Parsed records: {result['count']}",
        f"- Timestamps not verified as UTC: {result.get('unverified_timestamps', 0)}", "",
        "## Review candidates", "",
        "These event-ID indicators are **not proof of an attack**. Candidate ATT&CK mappings require independent corroboration.", "",
        "| Evidence ID | Timestamp | Host | Event ID | Observation | Severity | ATT&CK candidate |",
        "|---|---|---|---|---|---|---|",
    ]
    def clean(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    for event in result["events"]:
        lines.append("| " + " | ".join(clean(event[key]) for key in (
            "evidence_id", "timestamp", "host", "event_id", "finding", "severity", "mitre_candidate"
        )) + " |")
    lines += ["", "## Event sequence candidates", ""]
    if result.get("sequences"):
        for seq in result["sequences"]:
            lines.append(
                f"- **{clean(seq['sequence'])}** — `{seq['first_evidence_id']}` → "
                f"`{seq['second_evidence_id']}` within {seq['elapsed_minutes']} min "
                f"on `{clean(seq['host'])}`. {clean(seq['review_note'])}"
            )
    else:
        lines.append("No configured sequence candidates were observed.")
    lines += [
        "", "## Analyst notes (unverified)", "",
        analyst_notes.strip() or "_No analyst notes provided._", "",
        "## Recommended validation", "",
        "1. Confirm log collection coverage, source authenticity, and timestamp context.",
        "2. Correlate Windows logon IDs, host processes, account changes, and change records.",
        "3. Review each ATT&CK candidate manually; do not infer malicious intent from a single event ID.",
        "4. Preserve originals, record handling procedures, and document analyst decisions.", "",
        "## Limitations", "",
        "This educational prototype is not an EVTX parser, SIEM replacement, full chain-of-custody system, "
        "or validated forensic expert system. Unparsed or naive timestamps may not sort chronologically. "
        "AI text, if generated separately, is advisory and is not incorporated as verified evidence.", "",
    ]
    return "\n".join(lines)
