# Investigation Report #1 — Spoofing / Credential Phishing

## 1. Executive Summary
On October 20, 2026, the SOC investigated a suspicious inbound email targeting `d.martinez@global-corp.com` claiming to be an urgent invoice review from "Executive Finance Team". Technical evaluation confirmed exact domain spoofing in the `From` header (`executive-board-corp.com`), causing SPF, DKIM, and DMARC verification failures. The embedded link utilized a lookalike subdomain structure (`auth-verify-login[.]net`) to harvest corporate credentials. Web proxy telemetry confirmed that the user clicked the link and submitted credentials to an external authentication API (`/api/v1/auth`), resulting in a confirmed credential compromise. Immediate session revocation, password resets, and perimeter blocking were executed.

---

## 2. Incident Scenario & Initial Telemetry

### Scenario Context
- **Alert Source:** User Ticket / Phishing Report
- **Target Account:** `d.martinez@global-corp.com`
- **Workstation / Endpoint IP:** `HOST-FIN-04` (`10.10.4.12`)
- **Delivery Timestamp:** `2026-10-20T09:14:22Z`

### Raw Inbound Mail Gateway Headers
```email
Received: from mail-out.vendor-portal-update.com (mail-out.vendor-portal-update.com [198.51.100.88])
    by mx.global-corp.com (MTA v8.1) with ESMTP id 44829104
    for <d.martinez@global-corp.com>; Tue, 20 Oct 2026 09:14:22 +0000
Received-SPF: softfail (google.com: domain of transitioning domain of service@executive-board-corp.com does not designate 198.51.100.88 as permitted sender) client-ip=198.51.100.88;
Authentication-Results: mx.global-corp.com;
    spf=softfail (sender IP is 198.51.100.88) smtp.mailfrom=service@executive-board-corp.com;
    dkim=fail header.i=@executive-board-corp.com header.s=s1 header.b=X9a2;
    dmarc=fail (p=quarantine; dis=quarantine) header.from=executive-board-corp.com;
From: "Executive Finance Team" <service@executive-board-corp.com>
Reply-To: <accounts-payable@vendor-portal-update.com>
To: "Daniel Martinez" <d.martinez@global-corp.com>
Subject: URGENT: Outstanding Q3 Invoice Review Required
Date: Tue, 20 Oct 2026 09:14:18 +0000
Message-ID: <20261020091418.883921@vendor-portal-update.com>
Content-Type: text/html; charset="UTF-8"
```

### Email Body Content
```text
From: Executive Finance Team <service@executive-board-corp.com>
Subject: URGENT: Outstanding Q3 Invoice Review Required

Dear Daniel,

Please review the attached overdue vendor invoice immediately to avoid service suspension for Q4.
You can review and approve the document securely using our corporate portal:

hxxps://executive-board-corp.com.auth-verify-login[.]net/login?ref=d.martinez@global-corp.com

Thank you,
Corporate Finance Department
Executive Board Corp
```

### Web Proxy & Endpoint Logs (`HOST-FIN-04`)
| Timestamp (UTC) | Source Host / IP | Process / User | Action | Destination URL / Address | HTTP Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `09:14:22Z` | Gateway (`MTA-01`) | Mail Delivery | Delivered | `d.martinez@global-corp.com` | Delivered to Inbox |
| `09:18:04Z` | `HOST-FIN-04` (`10.10.4.12`) | `chrome.exe` (`d.martinez`) | GET | `hxxps://executive-board-corp.com.auth-verify-login[.]net/login?ref=d.martinez@global-corp.com` | `200 OK` (342 KB) |
| `09:18:45Z` | `HOST-FIN-04` (`10.10.4.12`) | `chrome.exe` (`d.martinez`) | POST | `hxxps://executive-board-corp.com.auth-verify-login[.]net/api/v1/auth` | `302 Found` (Redirected) |

---

## 3. Investigation & Analyst Findings

### 3.1 Header & Authentication Alignment Analysis
- **Sender Infrastructure Mismatch:** The message arrived from `198.51.100.88` (`mail-out.vendor-portal-update.com`), claiming to be `service@executive-board-corp.com` in the `From` header and instructing replies to `accounts-payable@vendor-portal-update.com`.
- **SPF Evaluation:** `SoftFail`. The sending MTA IP (`198.51.100.88`) is not designated in the published SPF record for domain `executive-board-corp.com`.
- **DKIM Evaluation:** `Fail`. The DKIM signature failed cryptographic verification (`header.i=@executive-board-corp.com`).
- **DMARC Evaluation:** `Fail`. Because neither SPF nor DKIM authenticated or aligned with the RFC 5322 `From` domain (`executive-board-corp.com`), DMARC evaluation failed under the domain's quarantine policy (`p=quarantine`).

### 3.2 Spoofing Strategy Assessment
- **Header Level:** **Exact Domain Spoofing**. The threat actor directly claimed identity as `executive-board-corp.com` without authorization.
- **URL Level:** **Lookalike Subdomain Abuse**. The adversary prepended the trusted brand name (`executive-board-corp.com`) as a prefix subdomain on an attacker-owned root domain (`auth-verify-login[.]net`).

### 3.3 User Interaction & Scoping
- **Landing Page Access:** At `09:18:04Z`, user `d.martinez` opened the link in Google Chrome, triggering an HTTP `GET` request (`200 OK`, 342 KB payload rendered).
- **Credential Harvesting:** At `09:18:45Z`, an HTTP `POST` request was sent to `/api/v1/auth`, confirming that the user submitted authentication credentials into the phishing form.
- **Evasion / Redirection:** The server responded with HTTP `302 Found`, redirecting the user back to the legitimate `executive-board-corp.com` site to hide the compromise.
- **Verdict:** Confirmed Credential Compromise.

---

## 4. Indicators of Compromise (IOCs)

| IOC Type | Value | Context |
| :--- | :--- | :--- |
| **Sending IPv4** | `198.51.100.88` | Unverified inbound MTA IP |
| **Spoofed Domain** | `executive-board-corp.com` | Domain impersonated in `From:` header |
| **Reply-To Domain** | `vendor-portal-update.com` | Unaligned return address |
| **Attacker Root Domain** | `auth-verify-login[.]net` | Infrastructure hosting phishing portal |
| **Phishing URL (Landing)** | `hxxps://executive-board-corp.com.auth-verify-login[.]net/login` | Phishing landing page URI |
| **Harvest Endpoint** | `hxxps://executive-board-corp.com.auth-verify-login[.]net/api/v1/auth` | Credential collection endpoint |

---

## 5. Recommended Response & Remediation

1. **Identity Containment:** Immediately revoke all active OAuth sessions and execute a forced password reset for `d.martinez@global-corp.com`.
2. **Post-Compromise Audit:** Query Entra ID `SigninLogs` and `AuditLogs` for `d.martinez` starting at `09:18:45Z` to verify no secondary MFA devices, OAuth permissions, or hidden inbox rules were registered.
3. **Perimeter Blocks:** Add IP `198.51.100.88` and root domain `auth-verify-login[.]net` to blocklists across perimeter firewalls, web proxies, and gateway security filters.
4. **Tenant Search & Purge:** Issue an Exchange Online search and purge command for Message-ID `<20261020091418.883921@vendor-portal-update.com>` to soft-delete/hard-delete matching emails from all internal inboxes.

---

## 6. Telemetry Limitations & Uncertainty
- Proxy logs confirm HTTP `POST` credential submission, but lack SSL/TLS decryption to inspect payload content (e.g., whether MFA tokens or session cookies were captured).
- Endpoint logs confirm browser activity (`chrome.exe`), but local Sysmon process trees confirm no secondary binary executions or malware drops occurred on `HOST-FIN-04`.