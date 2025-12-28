# Required Attacks Checklist (Infrastructure & Abuse Component)

Since your component is **"AI ML Detection of DNS Abuse and Infrastructure Attacks"**, you must train your model on these specific attack types.

## 1. DNS Amplification Attack
*   **What it is**: Attackers send small queries to open resolvers to generate massive responses towards a victim.
*   **Key Features**:
    *   `dns_edns_present` = 1 (Using EDNS).
    *   `dns_edns_udp_size` > 4096 (Requesting huge buffer).
    *   `dns_query_type` = 255 (ANY) or 16 (TXT).
    *   `dns_response_size` = HUGE.
*   **Why**: The classic "Infrastructure killer" (volumetric DDoS).

## 2. DNS Reflection Attack
*   **What it is**: Similar to Amplification, but focusing on the "Reflection" aspect (spoofed Source IP).
*   **Key Features**:
    *   `dns_answer_count` > 10 (Many answers in one packet).
    *   `dns_rcode` = 0 (NoError).
*   **Why**: Fills the victim's download bandwidth.

## 3. Water Torture (random Subdomain Flag)
*   **What it is**: Flooding a Recursive Resolver with millions of queries for non-existent subdomains (`abc.google.com`, `xyz.google.com`).
*   **Key Features**:
    *   `nxdomain_rate` = ~1.0 (Approx 100% Errors).
    *   `dns_unique_domains` = VERY HIGH (thousands).
    *   `dns_rcode` = 3 (NXDOMAIN).
*   **Why**: Exhausts the CPU and RAM of the DNS Resolver (Resource Exhaustion).

## 4. DNS Query Flood (UDP Flood)
*   **What it is**: Simply sending legitimate-looking queries as fast as possible to crash the server.
*   **Key Features**:
    *   `queries_per_second` = EXTREME (> 100/sec).
    *   `dns_qr` = 0 (Lots of Questions).
    *   `dns_total_responses` = Low/Zero (Server can't keep up).
*   **Why**: Standard Denial of Service (DoS).

## 5. DNS Cache Poisoning (Spoofing)
*   **What it is**: Injecting fake DNS records into a recursive resolver's cache.
*   **Key Features**:
    *   `dns_answer_ttls_mean` = Abnormal (Attacker sets specific TTLs).
    *   `dns_opcode` = 5 (Update) or standard response without a query.
    *   *(Note)*: Harder to detect with flows, but `Answer Count` and `TTL` anomalies give it away.
*   **Why**: Redirects users to malicious sites (Infrastructure Integrity attack).

## 6. DNS TCP SYN Flood (Infrastructure Exhaustion)
*   **What it is**: Flooding Port 53 (TCP) with SYN packets to fill the server's connection table.
*   **Key Features**:
    *   `Protocol` = TCP.
    *   `Dst Port` = 53.
    *   `Flag` = SYN only (No ACK).
    *   **Note**: Your tool captures this flow, but `dns_opcode` etc. might be empty if the handshake never completes. The *Volume* and *Protocol* are the indicators.
*   **Why**: Kills the server's ability to handle legitimate TCP DNS (like Zone Transfers or large responses).

---

## Data Collection Plan
You need to find PCAP files for these categories:
1.  [ ] **Amplification** (Look for "DNS ANY" or "DNS TXT" attacks).
2.  [ ] **Reflection** (Often combined with Amplification).
3.  [ ] **Water Torture** (Look for "NXDOMAIN Flood" or "DGA").
4.  [ ] **Query Flood** (Look for "UDP 53 Flood").
5.  [ ] **Cache Poisoning** (Look for "DNS Spoofing").
6.  [ ] **DNS SYN Flood** (Look for "TCP Port 53 Flood").
