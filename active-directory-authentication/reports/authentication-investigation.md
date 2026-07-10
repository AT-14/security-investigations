# Authentication Investigation
## 1. Summary

This investigation analyzed Active Directory authentication activity within a Windows domain environment using Windows Security Event Logs and Splunk Enterprise. The objective was to understand how successful, failed, Kerberos, and NTLM authentication events appear in enterprise telemetry and how they can be correlated during a SOC investigation.

Successful logons, Kerberos authentication, privileged logons, logoff events, and account lockout activity were successfully validated. A telemetry limitation was encountered where newly generated failed logon events (Event ID 4625) were not consistently recorded despite repeated testing. Existing historical telemetry and Event Viewer evidence were therefore used to complete the investigation.

---

## 2. Objective

- Investigate Windows authentication activity in an Active Directory environment.
    
- Correlate authentication-related Windows Security Events.
    
- Differentiate successful, failed, Kerberos, and NTLM authentication.
    
- Understand how authentication events support SOC investigations.
    

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
|4624|Successful Logon|Verified|
|4625|Failed Logon|Investigated using historical evidence|
|4634|Logoff|Verified|
|4672|Special Privileges Assigned|Verified|
|4740|Account Lockout|Verified|
|4768|Kerberos Authentication (TGT Issued)|Verified|
|4769|Kerberos Service Ticket|Verified|
|4776|NTLM Authentication|Verified|

Observed logon types:

- Interactive (Type 2)
    
- Network (Type 3)
    
- Service (Type 5)
    

Authentication mechanisms observed:

- Kerberos
    
- NTLM
    

---

## 5. Analysis

The investigation demonstrated the normal Active Directory authentication workflow. Successful domain logons generated Event ID 4624, while Kerberos authentication generated Event IDs 4768 and 4769 as expected. NTLM authentication was also observed through Event ID 4776.

Privileged logons generated Event ID 4672 immediately after successful authentication, indicating that Windows assigned elevated privileges to the authenticated account.

Logoff activity was successfully correlated using Event ID 4634, allowing authentication sessions to be reconstructed chronologically.

Repeated attempts were made to generate new failed authentication events from the domain-joined client using multiple methods. Although successful domain authentication consistently produced Event ID 4624, newly generated Event ID 4625 entries did not appear on the Domain Controller. Existing historical telemetry and Event Viewer evidence were therefore used to analyze failed authentication behavior. This limitation was documented rather than ignored because accurately reporting telemetry limitations is an important part of professional SOC investigations.

---

## 6. Authentication Timeline

1. User initiates authentication.
    
2. Domain Controller validates credentials.
    
3. Kerberos issues a Ticket Granting Ticket (Event ID 4768).
    
4. Service tickets are requested when required (Event ID 4769).
    
5. Windows creates the authenticated logon session (Event ID 4624).
    
6. Privileged accounts receive elevated privileges (Event ID 4672 when applicable).
    
7. Authentication may also occur using NTLM (Event ID 4776).
    
8. User logoff generates Event ID 4634.
    
9. Failed authentication attempts normally generate Event ID 4625, although new occurrences could not be reproduced during this investigation due to a telemetry limitation.
    

---

## 7. Conclusion

The investigation successfully validated the primary Windows authentication events used during Active Directory investigations. Authentication telemetry demonstrated both Kerberos and NTLM authentication workflows and provided sufficient evidence to correlate successful logons, privileged activity, logoff events, account lockouts, and service ticket generation.

Although new failed authentication events could not be consistently reproduced, sufficient historical evidence was available to understand their investigative value. This reinforces the importance of correlating multiple authentication events instead of relying on a single Event ID during enterprise investigations.

---

## 8. SOC Recommendations

- Monitor authentication activity by correlating Events 4624, 4625, 4672, 4768, 4769, and 4776.
    
- Investigate repeated failed logons from the same source or across multiple accounts.
    
- Review privileged logons immediately after Event ID 4672 is generated.
    
- Validate telemetry pipelines regularly to ensure Security Events are consistently collected by the SIEM.
    
- Correlate authentication events with account lockouts and group membership modifications to identify potential identity-based attacks.
    

---

## 9. Lessons Learned

- Kerberos authentication begins with Event ID 4768 before Windows creates the successful logon session (4624).
    
- Both Kerberos and NTLM authentication should be understood because enterprise environments often use both.
    
- Authentication investigations require correlating multiple events rather than relying on a single Event ID.
    
- Accurate documentation of telemetry limitations is an essential part of professional SOC investigations.
    
- Windows Security Events provide sufficient evidence to reconstruct user authentication activity and support incident investigations.
