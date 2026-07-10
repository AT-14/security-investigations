# Active Directory Authentication

## Overview

This project documents the investigation of authentication activity within a Windows Active Directory environment. The work focuses on understanding how identity-related events are generated, collected, investigated, and detected using Windows Security Event Logs, Event Viewer, and Splunk Enterprise.

The project covers successful and failed authentication, Kerberos and NTLM authentication, privileged account activity, service account authentication, Active Directory group membership modifications, investigation reporting, and detection engineering.

---

## Lab Environment

| Component | Technology |
|-----------|------------|
| Domain Controller | Windows Server 2022 |
| Client | Windows 10 (Domain Joined) |
| SIEM | Splunk Enterprise |
| Log Sources | Windows Security Logs, Event Viewer |
| Domain | `corp.contoso.com` |

---

## Project Structure

```text
active-directory-authentication/
│
├── reports/
│   ├── authentication-investigation.md
│   └── privileged-activity-investigation.md
│
├── detection-rules/
│   ├── account_lockout.md
│   ├── password_spraying.md
│   ├── privileged_group_modification.md
│   └── images/
│       ├── account_lockout.png
│       ├── password_spraying.png
│       └── privileged_group_modification.png
│
└── README.md
```

---

## Authentication Events Investigated

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4634 | Logoff |
| 4672 | Special Privileges Assigned |
| 4740 | Account Lockout |
| 4768 | Kerberos Ticket Granting Ticket (TGT) |
| 4769 | Kerberos Service Ticket |
| 4776 | NTLM Authentication |
| 4728 | Member Added to Security-Enabled Global Group |
| 4732 | Member Added to Security-Enabled Local Group |

---

## Investigation Reports

### Authentication Investigation

Focuses on:

- Successful authentication
- Failed authentication
- Kerberos authentication
- NTLM authentication
- Account lockout activity
- Authentication timeline reconstruction

### Privileged Activity & Identity Investigation

Focuses on:

- Privileged administrator authentication
- Service account authentication
- Kerberos authentication workflow
- Active Directory group membership changes
- Identity-focused SOC investigations

---

## Detection Rules

The project includes three detection rules developed and validated during the investigation.

| Detection | Purpose |
|-----------|---------|
| Password Spraying | Detect a single source attempting authentication against multiple accounts |
| Account Lockout | Detect user account lockouts indicating potential credential attacks |
| Privileged Group Modification | Detect unauthorized modifications to Active Directory security groups |

Each detection includes:

- MITRE ATT&CK mapping
- SPL query
- Detection validation
- Investigation guidance
- False positives
- Severity assessment
- Recommended SOC response

A validation screenshot is provided immediately after each SPL query to demonstrate successful execution within the lab environment.

---

## Skills Demonstrated

- Active Directory investigations
- Windows Security Event analysis
- Kerberos authentication analysis
- NTLM authentication analysis
- Privileged account monitoring
- Service account analysis
- Active Directory administration auditing
- Splunk SPL development
- Detection engineering fundamentals
- Professional SOC reporting

---

## Notes

During the lab, authentication telemetry forwarding to Splunk was intermittently inconsistent. Where appropriate, Windows Event Viewer was used to validate Security Events. This limitation is documented within the relevant investigation reports and detection rules to accurately reflect the investigation process.