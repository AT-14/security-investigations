# Privileged Activity Investigation
## 1. Summary

This investigation examined privileged authentication, service account activity, and Active Directory group membership changes within a Windows domain environment. The objective was to identify how identity-related events are recorded, understand the security significance of privileged accounts and service accounts, and investigate administrative changes that could indicate privilege escalation or unauthorized access.

The investigation successfully validated privileged logons, Kerberos authentication performed by service accounts, and Active Directory group membership modifications. These activities represent some of the highest-value telemetry monitored by Security Operations Centers because they directly affect identity, authorization, and privilege within an enterprise.

---

## 2. Objective

- Investigate privileged account activity.
    
- Validate service account authentication.
    
- Analyze Active Directory group membership changes.
    
- Understand the security implications of identity-related events.
    
- Correlate authentication and authorization events into a single investigation.
    

---

## 3. Environment

|Component|Value|
|---|---|
|Investigation Date|9 July 2026|
|Domain|corp.contoso.com|
|Domain Controller|Windows Server 2022|
|Client|Windows 10 (Domain Joined)|
|SIEM|Splunk Enterprise|
|Log Sources|Windows Security Logs, Event Viewer|

---

## 4. Evidence Collected

|Event ID|Description|Investigation Result|
|---|---|---|
|4624|Successful privileged authentication|Verified|
|4672|Special privileges assigned|Verified|
|4768|Kerberos Ticket Granting Ticket issued|Verified|
|4728|Member added to a security-enabled global group|Verified|

Accounts investigated:

- **itadmin** (Privileged Administrator)
    
- **svc_sql** (SQL Service Account)
    
- **svc_web** (Web Service Account)
    

---

## 5. Analysis

### Privileged Account Authentication

The dedicated administrative account **itadmin** successfully authenticated to the domain. Windows generated Event ID **4624**, followed immediately by Event ID **4672**, confirming that elevated privileges were assigned to the session.

From a SOC perspective, Event ID 4672 is significant because it identifies sessions that receive powerful privileges. Although this behavior is expected for legitimate administrators, the same telemetry is frequently reviewed during investigations involving privilege escalation, compromised administrator credentials, or unauthorized administrative access.

---

### Service Account Authentication

Both **svc_sql** and **svc_web** authenticated successfully using Kerberos.

For each authentication, Event ID **4768** was generated before Event ID **4624**.

This sequence reflects the expected Kerberos authentication workflow:

1. The client requests a Ticket Granting Ticket (TGT).
    
2. The Domain Controller validates the credentials.
    
3. The KDC issues the TGT (Event ID 4768).
    
4. Windows creates the authenticated logon session (Event ID 4624).
    

This confirmed that both service accounts were authenticating through Kerberos rather than NTLM.

Service accounts deserve particular attention during SOC investigations because they often execute automated services, scheduled jobs, databases, web applications, or enterprise software. Due to their elevated privileges and long-lived credentials, compromised service accounts frequently become persistence mechanisms for attackers.

---

### Active Directory Group Membership Modification

A group membership modification was performed within Active Directory.

Event ID **4728** recorded the change and identified:

- The administrator performing the action.
    
- The account added to the group.
    
- The affected security group.
    
- The Active Directory domain in which the modification occurred.
    

This event is highly valuable because unauthorized group membership changes may indicate privilege escalation or persistence. Attackers commonly attempt to add compromised accounts to privileged security groups to maintain elevated access after initial compromise.

The investigation also reinforced the distinction between:

- **4728** — Member added to a security-enabled **global** group.
    
- **4732** — Member added to a security-enabled **local** group.
    

Understanding this distinction improves the analyst's ability to interpret administrative activity correctly.

---

## 6. Timeline

1. Administrative account authenticated successfully.
    
2. Elevated privileges assigned to the session (4672).
    
3. Service account **svc_sql** requested a Kerberos TGT (4768).
    
4. Windows created the authenticated session for **svc_sql** (4624).
    
5. Service account **svc_web** requested a Kerberos TGT (4768).
    
6. Windows created the authenticated session for **svc_web** (4624).
    
7. Active Directory group membership was modified (4728).
    

---

## 7. Conclusion

The investigation successfully validated several critical identity-related activities within Active Directory.

Privileged authentication, Kerberos-based service account authentication, and security group modifications all generated the expected telemetry, allowing authentication and authorization events to be reconstructed into a complete investigation timeline.

These events represent high-value monitoring targets because they provide direct visibility into administrative activity, service identity usage, and privilege changes throughout the enterprise.

---

## 8. SOC Recommendations

- Continuously monitor privileged logons (4624 + 4672).
    
- Baseline expected service account behavior and investigate unusual authentication times or source systems.
    
- Alert on all privileged group membership modifications (4728, 4732).
    
- Correlate privileged authentication with subsequent administrative actions.
    
- Review newly added privileged group members for authorization and business justification.
    

---

## 9. Lessons Learned

- Privileged authentication generates additional telemetry beyond a standard user logon.
    
- Event ID 4672 is one of the most valuable indicators of administrative activity.
    
- Kerberos authentication consistently begins with Event ID 4768 before Windows creates the authenticated session.
    
- Service accounts should be monitored separately from user accounts because they often possess elevated privileges and operate continuously.
    
- Unauthorized security group modifications are high-confidence indicators of potential privilege escalation and should always be investigated promptly.
