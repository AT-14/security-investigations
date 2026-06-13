# TryHackMe — Snort Challenge: Live Attacks

**Category:** Blue Team / SOC  
**Difficulty:** Medium

---

## 🎯 Objective

Detect and stop live malicious network activity using Snort by analyzing traffic in sniffer mode, identifying attack patterns, writing custom IPS rules, and enforcing blocks in inline IPS mode.

---

## 🧠 Key Concepts

- Brute-force attack detection
- Reverse shell identification
- Snort sniffer vs IPS modes
- Custom Snort rule creation
- Inline traffic blocking (AFPacket DAQ)

---

## 🔍 Investigation Workflow

### Data & Context

**J&Y Enterprise**, a top tech-coffee retailer, was targeted by attackers seeking their super-secret recipe **"Shot4J"**. The company received multiple attacks and required immediate security support to protect their digital assets.

---

### 2️⃣ Analysis Process

#### Scenario 1 — Brute-Force Attack

Snort was run in sniffer mode to identify the attack source, service, and port:
```bash
sudo snort -c /etc/snort/snort.conf -devq
```

Traffic was analyzed for suspicious patterns including repeated inbound connection attempts, same source IP targeting the same destination, and rapid retries with changing source ports.

**Observed Traffic Pattern:**
```
10.10.245.36:<ephemeral> -> 10.10.140.29:22 TCP
```

From the traffic pattern, the destination port number is **22**, which is used by default for SSH service. Payload inspection confirmed SSH-related traffic, indicating a brute-force attack against the SSH service.

To stop the attack, a custom Snort rule was created:
```
drop tcp 10.10.245.36 any -> 10.10.140.29 22 (msg:"Brute-Force Attack"; sid:1000001; rev:1;)
```

Snort was then run in IPS mode:
```bash
sudo snort -c /etc/snort/snort.conf -Q --daq afpacket --daq-mode inline -i eth0:eth1 -A full -l /var/log/snort/ -q
```

The malicious traffic was successfully blocked. After maintaining the block for over one minute, the flag appeared on the desktop, confirming successful mitigation.

---

#### Scenario 2 — Reverse Shell

Following the brute-force mitigation, focus shifted to outbound traffic analysis to detect potential compromised systems or insider threats. J.A.V.A. detected persistent outbound communication patterns.

Snort was run in sniffer mode:
```bash
sudo snort -c /etc/snort/snort.conf -devq
```

Traffic was reviewed for persistent outbound connections, unusual destination ports, and payload characteristics indicating command execution.

**Observed Traffic Pattern:**
```
10.10.196.55:54148 -> 10.10.144.156:4444 TCP
```

A large volume of packets was observed flowing from the internal system to an external IP on port **4444**. Payload inspection revealed data containing command execution output, strongly suggesting an active reverse shell connection.

Port **4444** is commonly associated with the **Metasploit Framework** during post-exploitation phases, particularly for reverse shell handlers.

To stop the reverse shell, a custom Snort rule with bidirectional blocking was created:
```
drop tcp 10.10.196.55 54148 <> 10.10.144.156 4444 (msg:"Reverse Shell Found"; sid:1000001; rev:1;)
```

Snort was run in IPS mode:
```bash
sudo snort -c /etc/snort/snort.conf -Q --daq afpacket --daq-mode inline -i eth0:eth1 -A full -l /var/log/snort/ -q
```

The reverse shell traffic was successfully blocked. After maintaining the block for over one minute, the flag appeared on the desktop, confirming successful mitigation.

---

## ✅ Challenge Answers

### Scenario 1 — Brute-Force Attack

**Stop the attack and get the flag (which will appear on your Desktop)**  
**Answer:** THM{81b7fef657f8aaa6e4e200d616738254}

**What is the name of the service under attack?**  
**Answer:** SSH

**What is the used protocol/port in the attack?**  
**Answer:** TCP/22

---

### Scenario 2 — Reverse Shell

**Stop the attack and get the flag (which will appear on your Desktop)**  
**Answer:** THM{0ead8c494861079b1b74ec2380d2cd24}

**What is the used protocol/port in the attack?**  
**Answer:** TCP/4444

**Which tool is highly associated with this specific port number?**  
**Answer:** Metasploit

---

## 📌 Lessons Learned

- Repeated SSH attempts with changing source ports indicate brute-force attacks
- Sniffer mode enables accurate service identification before rule deployment
- Outbound traffic monitoring is critical for detecting compromised systems
- Port 4444 is a strong indicator of Metasploit reverse shells
- Bidirectional rules ensure complete connection termination

---

## 🧠 SOC Perspective

- **Detection:** High-frequency authentication attempts and persistent outbound connections to non-standard ports should trigger alerts
- **Response:** Inline IPS enables real-time mitigation and prevents data exfiltration
- **Prevention:** Exposed services require continuous monitoring and egress filtering is essential against post-exploitation activity
