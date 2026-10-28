# Email & Identity Incident Investigations

This folder contains three related investigations focusing on malicious emails and the personal, endpoint, and identity compromise that follows them.

Each investigation covers a distinct scenario:

| Case | File | Focus |
| :--- | :--- | :--- |
| 1 | [`spoofing-credential-phishing.md`](spoofing-credential-phishing.md) | Exact-domain spoofing, SPF/DKIM/DMARC verification failures, credential harvesting via a lookalike authentication portal |
| 2 | [`compromised-mailbox-bec.md`](compromised-mailbox-bec.md) | Account takeover via MFA prompt bombarding, rogue MFA registration, stealthy forwarding and inbox rules, fraudulent wire-transfer attempt (BEC) |
| 3 | [`email-to-identity-compromise.md`](email-to-identity-compromise.md) | Email-to-endpoint attack chain: encoded PowerShell staging, payload retrieval, registry persistence, C2 communication, Entra ID privilege escalation, rogue service principal |

## Skills Demonstrated

* Email header and gateway log analysis (Received path, Return-Path, Reply-To)
* SPF, DKIM, and DMARC interpretation and sender alignment
* Entra ID sign-in and audit log analysis
* Mailbox activity and forwarding abuse detection
* Web proxy and endpoint telemetry correlation
* IOC extraction, defanging, and threat intelligence enrichment
* Attack-chain and timeline reconstruction
* Evidence-based impact assessment, remediation scoping, and root cause analysis
* Professional incident documentation

## Note

All investigations in this folder were conducted using training and lab scenarios with synthetic data. Malicious indicators are defanged (`hxxps://`, `[.]`, `[@]`) for safe documentation and sharing.
