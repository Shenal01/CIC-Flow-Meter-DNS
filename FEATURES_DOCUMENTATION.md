# Comprehensive DNS Feature Documentation

This document provides a deep dive into every feature extracted by the **Antigravity** tool. It explains **what** the feature is, **how** it is calculated (Direct vs. Derived), and **why** it is critical for cybersecurity (Attacks Detected).

---

## 1. Feature Categories & Definitions

### A. Header-Level Features (Protocol Misuse)
These features come directly from the standard DNS packet header. Attackers often manipulate these fields to break protocol rules or flood servers.

*   **`dns_qr`**
    *   **Meaning**: Query/Response Flag. Indicates if the flow contains a response.
    *   **Source**: **Direct** (Header Bit).
    *   **Attacks**: Query Floods (DoS). If a flow has thousands of packets but `dns_qr=0`, it means the attacker is flooding a server with questions and ignoring answers.
*   **`dns_opcode`**
    *   **Meaning**: Operation Code (e.g., Standard Query, Status, Notify).
    *   **Source**: **Direct** (Header Field).
    *   **Attacks**: `ANY` floods or Misuse. Attackers might use rare Opcodes (like `UPDATE`) to exploit server vulnerabilities.
*   **`dns_rcode`**
    *   **Meaning**: Response Code (e.g., NoError, NXDOMAIN, ServFail).
    *   **Source**: **Direct** (Header Field from last packet).
    *   **Attacks**: **DGA / Water Torture**. A high rate of `NXDOMAIN` (Code 3) is the strongest indicator of a Domain Generation Algorithm botnet.
*   **`dns_qdcount`, `dns_ancount`, `dns_nscount`, `dns_arcount`**
    *   **Meaning**: Count of records in Question, Answer, Authority, and Additional sections.
    *   **Source**: **Direct** (Header integers).
    *   **Attacks**: Malformed Packets / Amplification. Normal queries usually have 1 Question. If `qdcount > 1`, it might be an attempt to crash a parser.

### B. Query-Level Features (Tunneling & DGA)
These features characterize what the user is "asking" for.

*   **`dns_query_length`**
    *   **Meaning**: Average length of the requested domain name (e.g., `google.com` = 10, `a.long.encoded.string.malware.com` = 35).
    *   **Source**: **Direct** (String length of QNAME).
    *   **Attacks**: **DNS Tunneling**. Attackers hide data in long subdomains (e.g., `base64_password.attacker.com`). Long average length = Tunneling.
*   **`dns_query_type`**
    *   **Meaning**: The record type requested (A, AAAA, TXT, MX).
    *   **Source**: **Direct** (Integer ID).
    *   **Attacks**: **Amplification / Tunneling**.
        *   `TXT` records are often used for Tunneling (can hold text).
        *   `ANY` records are used for Amplification (small request -> huge reply).

### C. Response-Level Features (Infrastructure Agility)
These features analyze what the server sent back.

*   **`dns_answer_count`**
    *   **Meaning**: Total number of IP addresses or records returned in the answer.
    *   **Source**: **Direct** (Loop count of Answer section).
    *   **Attacks**: **Amplification**. If a single small query returns 50 IPs, it is likely an amplification attack.
*   **`dns_answer_ttls_mean` (Time To Live)**
    *   **Meaning**: The average time a record is allowed to be cached (in seconds).
    *   **Source**: **Derived**. $\frac{\sum \text{All TTLs}}{\text{Count of Records}}$.
    *   **Attacks**: **Fast Flux Botnets**. Legitimate sites (Google, Amazon) have high TTLs (300s - 86400s). Botnets use extremely low TTLs (0s - 60s) to rapidly switch IP addresses and evade blocking.
*   **`dns_answer_rrtypes`**
    *   **Meaning**: Count of *unique* resource record types in the answer.
    *   **Source**: **Direct** (Size of Set of Types).
    *   **Attacks**: Anomalous behavior.

### D. Flow-Level Features (Behavioral Statistics)
Computed by aggregating the entire conversation.

*   **`dns_unique_domains`**
    *   **Meaning**: How many distinct domains were queried in this single flow.
    *   **Source**: **Derived** (Count of unique QNAME strings).
    *   **Attacks**: **DGA / Water Torture**. A normal user usually queries one domain per flow. A botnet will query hundreds of random domains (`agxq.com`, `bbyz.com`...) in one flow.
*   **`dns_rrtype_entropy`**
    *   **Meaning**: The mathematical randomness (Shannon Entropy) of the requested Record Types.
    *   **Source**: **Derived**. $-\sum p(x) \log_2 p(x)$ of the Query Type distribution.
    *   **Attacks**: **Tunneling**. Encrypted or randomized traffic patterns often manifest as high statistical entropy compared to the predictable patterns of normal browsing.

### E. Rate & Temporal (Volumetric Flooding)
Features that relate to time and frequency.

*   **`queries_per_second`**
    *   **Meaning**: The speed of requests.
    *   **Source**: **Derived**. $\frac{\text{Total Queries}}{\text{Flow Duration (sec)}}$.
    *   **Attacks**: **DDoS (Query Flood)**. A human browses slowly. A bot sends 1,000 queries/sec to crash the server.
*   **`nxdomain_rate`**
    *   **Meaning**: Percentage of responses that were "Domain Not Found".
    *   **Source**: **Derived**. $\frac{\text{Count of NXDOMAIN Packets}}{\text{Total Response Packets}}$.
    *   **Attacks**: **Water Torture Attack**. Attackers flood a recursive resolver with random non-existent domains to exhaust its resources.

### F. Size & EDNS (Exploits)
Features related to packet size and extensions.

*   **`dns_edns_present`**
    *   **Meaning**: Whether the Extension Mechanisms for DNS (EDNS) is used.
    *   **Source**: **Direct** (Check for OPT Record Type 41).
    *   **Attacks**: **Amplification**. EDNS is required to legitimate large DNS responses, but attackers abuse it to force servers to send massive replies.
*   **`dns_response_size`**
    *   **Meaning**: Total bytes of all response packets.
    *   **Source**: **Derived** (Sum of payload lengths).
    *   **Attacks**: **Amplification (Reflection)**. If the `Response Size` is 50x larger than the `Query Size`, it is a reflection attack.

---

## 2. Final Summary Table

| Feature Name | Source | How It Is Derived | Detects Attack(s) | Reason |
| :--- | :--- | :--- | :--- | :--- |
| `dns_qr` | **Direct** | Header Bit | Query Flood | Distinguishes one-way floods from conversations. |
| `dns_opcode` | **Direct** | Header Field | Protocol Exploit | Rare opcodes target server bugs. |
| `dns_rcode` | **Direct** | Header Field | DGA / Water Torture | High error rates indicate random domain guessing. |
| `dns_qdcount` | **Direct** | Header Integer | Malformed Packet | Abnormally high counts crash parsers. |
| `dns_query_length`| **Direct** | String Length | **DNS Tunneling** | Long domains carry hidden payload data. |
| `dns_query_type` | **Direct** | Integer ID | Amplification | `ANY` or `TXT` types carry large payloads. |
| `dns_answer_count`| **Direct** | Loop Count | Amplification | Too many IPs in one reply is suspicious. |
| `dns_answer_ttls_mean`| **Derived**| Avg(TTLs) | **Fast Flux** | Low TTL (<60s) = Botnet infrastructure. |
| `dns_unique_domains`| **Derived**| Set Size | DGA / Random Subdomain| Asking for many *different* domains in one flow. |
| `dns_rrtype_entropy`| **Derived**| Shannon Formula | Tunneling (Encrypted) | High randomness = Encrypted data, not text. |
| `queries_per_second`| **Derived**| Count / Time | **DDoS (Flood)** | Super-human speed indicates automation. |
| `nxdomain_rate` | **Derived**| Count / Total | Water Torture | 100% error rate = Attack on Resolver resources. |
| `dns_edns_present`| **Direct** | Type Check | Amplification | Enables large payloads (>512 bytes). |
| `dns_response_size`| **Derived**| Sum(Bytes) | Amplification | Huge responses clog the network pipe. |
