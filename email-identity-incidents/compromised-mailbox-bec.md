# Investigation Report #2 — Compromised Mailbox / Business Email Compromise (BEC)

## 1. Executive Summary
On October 21, 2026, the SOC responded to a high-severity alert indicating suspicious inbox rule creation following an anomalous sign-in for `v.chen@global-corp.com` (Senior Accounts Payable Lead). Investigation of Entra ID and Exchange Online telemetry confirmed an Account Takeover (ATO) executed via MFA prompt bombarding from an anomalous geographic location (Amsterdam, NL). Following initial access, the threat actor registered a rogue authentication phone number, configured external SMTP forwarding to ProtonMail, established stealth inbox rules targeting financial keywords, and utilized legacy authentication (IMAP4) to issue fraudulent wire transfer instructions to an external vendor partner (`ap-team@vendor-partner.com`). Full identity isolation, artifact cleanup, and external vendor notification were executed immediately.

---

## 2. Incident Scenario & Raw Telemetry

### Scenario Context
- **Alert Source:** Microsoft Sentinel / Defender for Office 365
- **Target Account:** Victoria Chen (`v.chen@global-corp.com`) — Senior Accounts Payable Lead
- **Outbound Target:** Vendor Accounts Team (`ap-team@vendor-partner.com`)
- **Compromise Window:** `2026-10-21T05:45:12Z` – `2026-10-21T06:12:08Z`

### Inbound / Outbound Email Headers
```email
Received: from EUR02-DB6-obe.outbound.protection.outlook.com (mail-eur02.outbound.protection.outlook.com [40.92.48.34])
    by mx.vendor-partner.com (MTA v8.1) with ESMTP id 99281031
    for <ap-team@vendor-partner.com>; Wed, 21 Oct 2026 06:12:10 +0000
Authentication-Results: mx.vendor-partner.com;
    spf=pass (sender IP is 40.92.48.34) smtp.mailfrom=v.chen@global-corp.com;
    dkim=pass header.i=@global-corp.com header.s=selector1;
    dmarc=pass (p=reject; dis=none) header.from=global-corp.com;
From: "Victoria Chen" <v.chen@global-corp.com>
To: "Vendor Accounts Team" <ap-team@vendor-partner.com>
Subject: RE: Outstanding Inv #99402 - Updated Wire Transfer Instructions
Date: Wed, 21 Oct 2026 06:12:08 +0000
Message-ID: <EUR02-DB6-MSG-20261021061208@global-corp.com>
Content-Type: text/html; charset="UTF-8"
```

### Entra ID Sign-In Logs (`SigninLogs`)
| TimeGenerated (UTC) | UserPrincipalName | IPAddress | Location | ClientAppUsed | Status.errorCode | ConditionalAccessStatus | MFA Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-10-20T16:30:00Z` | `v.chen@global-corp.com` | `198.51.100.12` | US (New York) | Browser | `0` | `success` | Satisfied in session |
| `2026-10-21T05:45:12Z` | `v.chen@global-corp.com` | `185.220.101.42` | NL (Amsterdam) | Browser | `500121` | `notApplied` | MFA Prompt Denied |
| `2026-10-21T05:46:30Z` | `v.chen@global-corp.com` | `185.220.101.42` | NL (Amsterdam) | Browser | `0` | `success` | Mobile Push Approved |
| `2026-10-21T05:58:10Z` | `v.chen@global-corp.com` | `185.220.101.42` | IMAP4 | `0` | `notApplied` | Single-factor (Bypassed) |

### Entra ID Audit Logs (`AuditLogs`)
| TimeGenerated (UTC) | InitiatedBy | ActivityDisplayName | Target | Details / Modified Properties |
| :--- | :--- | :--- | :--- | :--- |
| `2026-10-21T05:50:15Z` | `v.chen@global-corp.com` | `User registered security info` | `v.chen@global-corp.com` | Added Mobile Phone: `+31 6 12345678` |

### Mailbox Activity Logs (`OfficeActivity`)
| TimeGenerated (UTC) | UserId | Operation | Parameters / Details |
| :--- | :--- | :--- | :--- |
| `2026-10-21T05:55:00Z` | `v.chen@global-corp.com` | `Set-Mailbox` | `ForwardingSmtpAddress: "finance-audit-backup@protonmail.com"`, `DeliverToMailboxAndForward: True` |
| `2026-10-21T06:02:18Z` | `v.chen@global-corp.com` | `New-InboxRule` | `Name: "SystemFilter"`, `SubjectContainsWords: ["invoice", "wire", "payment", "bank", "overdue"]`, `MoveToFolder: "RSS Subscriptions"`, `MarkAsRead: True` |

---

## 3. Investigation & Technical Findings

### 3.1 Infrastructure Authenticity & Sender Verification
* **Header Alignment:** SPF, DKIM, and DMARC evaluation all returned `PASS` on outgoing messages.
* **Authentication Conclusion:** The email originated directly from Microsoft 365 tenant outbound servers (`40.92.48.34`) using authentic domain credentials (`v.chen@global-corp.com`). This confirms legitimate account abuse following an Account Takeover (ATO) rather than external domain spoofing.

### 3.2 Authentication & Sign-In Analysis
* **Location Anomaly:** An impossible travel pattern was observed between US (New York) at `16:30 UTC` and Amsterdam, NL (`185.220.101.42`) at `05:45 UTC`.
* **Initial Access Vector:** At `05:45:12 UTC`, sign-in failed due to MFA denial (`errorCode: 500121`). At `05:46:30 UTC` (78 seconds later), sign-in succeeded (`errorCode: 0`), confirming **MFA Fatigue / Prompt Bombarding**.
* **Legacy Authentication:** At `05:58:10 UTC`, the actor established a non-MFA connection via `IMAP4` to maintain persistent mailbox polling.

### 3.3 Persistence & Stealth Mechanisms
1. **Control Plane Persistence:** Added rogue Dutch mobile number (`+31 6 12345678`) to Entra ID Authentication Methods at `05:50:15 UTC`.
2. **External Data Exfiltration:** Configured external SMTP auto-forwarding to `finance-audit-backup@protonmail.com` with `DeliverToMailboxAndForward: True` at `05:55:00 UTC`.
3. **Inbox Stealth Rule:** Created inbox rule `SystemFilter` at `06:02:18 UTC` redirecting incoming financial communications (`invoice`, `wire`, `payment`, `bank`, `overdue`) to `RSS Subscriptions` with `MarkAsRead: True` to suppress user awareness.

---

## 4. Indicators of Compromise (IOCs)
| IOC Type | Value | Context |
| :--- | :--- | :--- |
| **Attacker IPv4** | `185.220.101.42` | Anomaly sign-in source (NL) |
| **Exfiltration Email** | `finance-audit-backup@protonmail.com` | Unauthorized external SMTP forwarding destination |
| **Rogue MFA Number** | `+31 6 12345678` | Attacker secondary authentication method |
| **Malicious Inbox Rule** | `SystemFilter` | Stealth rule moving financial keywords to RSS folder |

---

## 5. Containment & Remediation Actions

### Immediate Identity Isolation
1. **Session Termination:** Executed global session revocation across all active browser and app tokens (`Revoke-MgUserSignInSession`).
2. **Credential Reset & Account Lock:** Performed mandatory password reset for `v.chen@global-corp.com` and temporarily disabled login access during triage.

### Artifact Cleanup
3. **MFA Method Removal:** Deleted rogue phone number `+31 6 12345678` from Entra ID security info.
4. **Exchange Persistence Removal:** Executed `Set-Mailbox -Identity v.chen@global-corp.com -ForwardingSmtpAddress $null` and removed the `SystemFilter` inbox rule.
5. **Legacy Auth Enforcement:** Disabled basic/legacy authentication protocols (`IMAP4`, `POP3`, `SMTP`) on the account and updated tenant Conditional Access policies to block legacy auth directory-wide.

### External Impact Containment
6. **Out-of-Band Vendor Notification:** Contacted `ap-team@vendor-partner.com` via verified phone channel to issue an immediate stop-payment notice regarding fraudulent wire instructions.
7. **Message Purge:** Issued tenant-wide purge command for Message-ID `<EUR02-DB6-MSG-20261021061208@global-corp.com>`.

---

## 6. Telemetry Limitations & Uncertainty
* **Initial Credential Exposure:** Initial vector by which the attacker obtained `v.chen`'s password (phishing, credential dump, or password spray) remains unknown due to lack of pre-incident endpoint logs.
* **Financial Exposure State:** Unconfirmed at time of report closure whether the vendor partner processed or initiated wire transfers prior to out-of-band notification.