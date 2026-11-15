# Source references for Windows event semantics and Wazuh exports

These primary references clarify event meanings and **field roles**. They do not validate the fictional case datasets or establish attack intent.

- Microsoft Learn — [4720: A user account was created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720). The `TargetSid` is the new account SID, while `SubjectUserName` is the actor.
- Microsoft Learn — [4732: A member was added to a security-enabled local group](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732). `TargetUserName` identifies the *group*, `MemberSid` identifies the *added account*.
- Microsoft Learn — [4625: An account failed to log on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625). Logon type and source network address require context.
- Wazuh Docs — [Archive data / JSON output files](https://documentation.wazuh.com/current/cloud-service/archive-data/configuration.html). `alerts.json` contains alerting events, whereas archive data may include events that did not trigger alerts when configured.

Use the current vendor documentation when deploying or interpreting real environments.
