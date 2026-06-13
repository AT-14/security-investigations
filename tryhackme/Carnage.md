# TryHackMe — Carnage

**Category:** Blue Team / SOC  
**Difficulty:** Medium  

---

## 🎯 Objective
Apply SOC-style analysis to a malicious packet capture to identify initial infection, payload delivery, C2 infrastructure, and post-infection activity using **Wireshark** and external intelligence (**VirusTotal**).

---

## 🧠 Key Concepts
- Malicious document delivery (malspam)
- HTTP-based payload delivery
- Cobalt Strike C2 identification
- SSL/TLS certificate analysis
- Post-infection beaconing
- SMTP-based malspam activity

---

## 🔍 Investigation Workflow

### Data & Context
Eric Fischer (Purchasing Dept, Bartell Ltd) opened a malicious Word document and enabled macros. Shortly after, suspicious outbound traffic was detected. A **PCAP** was provided for analysis.

---

### 2️⃣ Analysis Process

### Question 1 — First Malicious HTTP Connection
**Answer:** `2021-09-24 16:44:38`  
HTTP traffic was filtered using `http`. The first HTTP packet observed was identified as the initial malicious connection. Timestamp was recorded in **UTC** format.

---

### Question 2 — Downloaded ZIP File
**Answer:** `documents.zip`  
The ZIP file name was visible in the HTTP request of the same packet identified in Question 1.

---

### Question 3 — ZIP Hosting Domain
**Answer:** `attirenepal.com`  
The destination IP was resolved to its domain using **Statistics → Resolved Addresses**.

---

### Question 4 — File Inside ZIP
**Answer:** `chart-1530076591.xls`  
Following the HTTP stream revealed the ZIP contents in the server response and the name of the file appeared at the beginning of the response.

---

### Question 5 — Webserver Name
**Answer:** `LiteSpeed`  
Identified from the `Server` header in the HTTP response.

---

### Question 6 — Application Version
**Answer:** `PHP/7.2.34`  
Identified from the `X-Powered-By` HTTP response header.

---

## Question 7 — Malicious Download Domains
**Answer: finejewels.com.au, thietbiagt.com, new.americold.com**  
HTTPS traffic was filtered within the time window specified in the challenge hint using the filter:
  `tls && frame.time >= "2021-09-24 16:45:11" && frame.time <= "2021-09-24 16:45:30"`

Only connections that completed the handshake **and exchanged data** were considered.  
Resolved from IPs: `148.72.192.206`, `210.245.90.247` and `148.72.53.144`
Using **Statistics → Resolved Addresses**, these IP addresses were resolved to their domain names.

---

## Question 8 — Certificate Authority
**Answer: GoDaddy**  
The TLS handshake associated with the first malicious domain, **`finejewels.com.au`**, was inspected.  
By examining the **Transport Layer Security Section** in the server certificate packet, the **issuer** was identified as **GoDaddy**.

---

## Question 9 — Cobalt Strike C2 Server IP Addresses
**Answer: 185.106.96.158, 185.125.204.174**  
Cobalt Strike Servers are used as C2 servers and mostly runs on ports 80 , 8080 and 443. I filtered the traffic to be on port 80 8080 and 443 using the filter: 
  `tcp.port in {80 8080 443}`

Then going to **Statistics → Conversations → TCP**, and sorting the **number of packets exchanged** in descending order.  
This approach highlights long-lived or high-volume connections, which are characteristic of C2 communication.

The IP addresses associated with the most suspicious traffic were then searched on **VirusTotal**.  
By reviewing the **Community** tab, two IP addresses were confirmed to be identified as **Cobalt Strike C2 servers**.

---

## Question 10 — Host Header of the First Cobalt Strike Server
**Answer: ocsp.verisign.com**  
HTTP traffic involving the first Cobalt Strike IP address was isolated using the filter:
  `http && ip.addr == 185.106.96.158`
By following the relevant **HTTP stream**, the **Host header** was extracted directly from the HTTP request.

---

## Question 11 — Domain Name of the First Cobalt Strike Server
**Answer: survmeter.live**  
Searching the IP in **Statistics → Resolved Addresses**.

---

## Question 12 — Domain Name of the Second Cobalt Strike Server
**Answer: securitybusinpuff.com**  
Identified using the same method as Question 11.

---

## Question 13 — Post-Infection Traffic Domain
**Answer: maldivehost.net**  
Identified by filtering POST requests and resolving the destination IP.
  `http.request.method == "POST"`

---

## Question 14 — First Eleven Characters Sent to the Malicious Domain
**Answer: zLIisQRWZI9**  
Observed directly in the HTTP request line of the POST request.

---

## Question 15 — Length of the First Packet Sent to the C2 Server
**Answer: 281**  
Packet length identified in the **Frame** section.

---

## Question 16 — Server Header of the Post-Infection Domain
**Answer: Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4**  
Extracted from the HTTP response header after following the HTTP Stream.

---

## Question 17 — DNS Query Timestamp for IP Check API
**Answer: 2021-09-24 17:00:04**  
DNS traffic was filtered to identify API-related queries using:
 `dns && dns.qry.name contains "api" 

From the filtered results, two APIs appeared. Searching them on Google, the DNS query corresponding to **`api.ipify.org`** was identified as the one used for IP lookup, and the **timestamp** of the first packet was recorded in **UTC format**.

---

## Question 18 — IP Check API Domain
**Answer: api.ipify.org**  

---

## Question 19 — First MAIL FROM Address
**Answer: farshin@mailfa.com**  
SMTP traffic was filtered using the `smtp` display filter.  
The first **MAIL FROM** command was identified from the **Info** column or by following the **TCP stream**, and the sender address was recorded.

---

## Question 20 — SMTP Packet Count
**Answer: 1439**  
SMTP traffic was filtered using the `smtp` display filter.  
The **total number of packets** was obtained directly from the **Wireshark status bar** and recorded.

---

## 📌 Lessons Learned
- Practiced reconstructing an infection timeline using PCAP analysis.
- Became more efficient using Wireshark filters, streams, and statistics.

---

## 🧠 SOC Perspective
- **Detection:** Repeated POST requests and long-lived TLS sessions can indicate C2 activity.
- **Alerting:** Repeated outbound connections to uncommon external domains can be used as reliable alert indicators.
- **Investigation:** Enriching traffic with threat intelligence improves confidence and accuracy.
