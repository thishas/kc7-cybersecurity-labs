# A Rap Beef – My Analysis & Experience

## ✅ Analysis of Each Query

### 1. Employee Lookup
```kql
Employees
| where role == "CEO"
```
**Purpose:** Identifies the CEO of OWL Records. This is a common starting point because executives are often high-value phishing targets.  
**Insight:** Could be relevant for understanding if the CEO’s account was compromised or targeted.

### 2. Inbound Network Traffic Check
```kql
InboundNetworkEvents
| where timestamp between (datetime("2024-04-10T00:00:00") .. datetime("2024-04-11T00:00:00"))
| where src_ip has "18.66.52.227"
```
**Purpose:** Filters inbound requests from a suspicious IP 18.66.52.227 during a specific timeframe.  
**Insight:** This IP likely belongs to the attacker. Logs show repeated attempts to gather info from OWL Records.

### 3. Passive DNS Resolution
```kql
PassiveDns
| where ip == "18.66.52.227"
```
**Purpose:** Resolves the suspicious IP to a domain name, confirming if it’s linked to any malicious infrastructure.  
**Insight:** Helps correlate IP with phishing or malicious domains.

### 4. Email Sampling
```kql
Email
| take 10
```
**Purpose:** Quickly inspects a subset of emails, likely to check for suspicious links or patterns.  
**Insight:** Initial reconnaissance of email data.

### 5. Search for Malicious Links
```kql
Email
| where link has "betterlyrics4u.com"
```
**Purpose:** Detects phishing attempts targeting employees.  
**Insight:** betterlyrics4u.com is the malicious domain used for phishing.

### 6. Identify Targeted Employees
```kql
let _targets = Email
| where link has "betterlyrics4u.com"
| distinct recipient;
Employees
| where email_addr in (_targets)
```
**Purpose:** Finds employees who clicked or received emails with that phishing link.  
**Insight:** Attackers focused on specific high-value employees. Possible compromise risk.

### 7. Confirm Outbound Connection
```kql
OutboundNetworkEvents
| where url == "http://betterlyrics4u.com/share/online/published/enter"
| where src_ip == "10.10.0.5"
```
**Purpose:** Confirms if any internal host accessed the malicious URL.  
**Insight:** Device with IP 10.10.0.5 connected to the phishing site—likely compromised.

### 8. Authentication Check
```kql
AuthenticationEvents
| where username == "dwaudrey"
| where src_ip == "18.66.52.227"
```
**Purpose:** Checks if the attacker attempted to log in as dwaudrey (Dwake).  
**Insight:** Credential stuffing or brute force attempts from the attacker’s IP.

### 9. Follow-Up Recon
```kql
InboundNetworkEvents
| where timestamp between (datetime("2024-04-12T00:00:00") .. datetime("2024-05-01T00:00:00"))
| where url has "dwaudrey" 
| where src_ip has "18.66.52.227"
```
**Purpose:** Monitors for ongoing attacks related to Dwake after initial compromise attempt.  
**Insight:** Persistence attempts detected—attacker kept probing.

---

## ✅ Key Findings

- **Attack Vector:** Phishing email via malicious domain betterlyrics4u.com.
- **Target:** Employees connected to OWL Records; Dwake specifically singled out.
- **Compromise Evidence:** Internal IP 10.10.0.5 accessed malicious link.
- **Attacker Behavior:** Recon via company site → Phishing campaign → Brute force attempt on Dwake’s account → Continued probing.
- **Threat Actor IP:** 18.66.52.227 linked to multiple malicious activities.

---

## ✅ Recommendations

- Block betterlyrics4u.com and the IP 18.66.52.227.
- Quarantine device 10.10.0.5, perform forensic analysis.
- Reset credentials for dwaudrey and other targeted employees.
- Educate staff about phishing awareness (since attackers use social engineering).
- Monitor for recurring attacks and update threat intelligence.
