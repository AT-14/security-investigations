# Registry Persistence Investigation

This project documents a Windows persistence investigation involving a Registry Run key and PowerShell execution.

The lab simulates a harmless persistence scenario, then investigates the activity using Sysmon, PowerShell Operational logs, Windows Security logs, and Splunk.

## Project Contents

### Investigation

The investigation report documents:

- PowerShell execution of `update.ps1`
- Registry Run key persistence
- Sysmon Event ID 1 process creation
- Sysmon Event ID 13 Registry modification
- PowerShell Event ID 4104 script block logging
- Windows Security Event ID 4624 user logon
- Process and timeline correlation
- MITRE ATT&CK mapping

[Read the registry persistence investigation](./investigation/registry-persistence-investigation.md)

### Detection Rules

The detection rules cover related Windows and PowerShell activity:

- Encoded PowerShell execution
- Registry Run / RunOnce key modification
- Scheduled task creation

Files:

- [Encoded PowerShell Detection](./detection-rules/encoded_powershell_detection.md)
- [Registry Run/RunOnce Key Modification](./detection-rules/registry_run_runonce_key_modification.md)
- [Scheduled Task Creation Detection](./detection-rules/scheduled_task_creation_detection.md)

## MITRE ATT&CK

| Technique | ID |
|---|---|
| [Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| [PowerShell](https://attack.mitre.org/techniques/T1059/001/) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| [Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |

## Repository Structure

```text
registry-persistence/
├── README.md
├── investigation/
│   ├── registry-persistence-investigation.md
│   └── images/
└── detection-rules/
    ├── encoded_powershell_detection.md
    ├── registry_run_runonce_key_modification.md
    ├── scheduled_task_creation_detection.md
    └── images/
```

## Environment

- Windows 11
- Sysmon
- PowerShell logging
- Windows Security logs
- Splunk
