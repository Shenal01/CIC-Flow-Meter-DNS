# Wireshark Testing & Feature Verification Guide

This document explains every extracted DNS feature, how it is derived (Direct from packet vs. Calculated), and the exact Wireshark filter to use for verification.

## 1. Header-Level Features (Protocol Misuse)

| Feature | Type | Source Logic | Wireshark Filter / Verification |
| :--- | :--- | :--- | :--- |
| **`dns_qr`** | **Direct** | Reads the QR bit from the DNS header. If *any* response is seen in the flow, this is 1. | `dns.flags.response` (0=Query, 1=Response). Check if the flow contains any packet with `dns.flags.response == 1`. |
| **`dns_opcode`** | **Direct** | Reads the OpCode field (e.g., 0=Standard, 5=Update). Returns the last observed OpCode. | `dns.flags.opcode`. |
| **`dns_rcode`** | **Direct** | Reads the RCode field (e.g., 0=NoError, 3=NXDOMAIN). Returns the last observed RCode. | `dns.flags.rcode`. Common values: 0 (No Error), 3 (NXDOMAIN). |
| **`dns_qdcount`** | **Direct** | Sum of "Questions" counts from all packets in flow. | `dns.count.queries`. Select packet -> DNS -> "Questions". Sum this value for all packets. |
| **`dns_ancount`** | **Direct** | Sum of "Answer RRs" counts from all packets. | `dns.count.answers`. |
| **`dns_nscount`** | **Direct** | Sum of "Authority RRs" counts from all packets. | `dns.count.auth_rr`. |
| **`dns_arcount`** | **Direct** | Sum of "Additional RRs" counts from all packets. | `dns.count.add_rr`. |

---

## 2. Query-Level Features (Abuse Indicators)

| Feature | Type | Source Logic | Wireshark Filter / Verification |
| :--- | :--- | :--- | :--- |
| **`dns_query_length`**| **Direct** | Average length of the QNAME (domain string) in questions. | `dns.qry.name.len`. Click a query -> "Length". Average this across all queries. |
| **`dns_query_type`** | **Direct** | The numerical Type of the query (1=A, 28=AAAA, 16=TXT). Returns last observed. | `dns.qry.type`. |

---

## 3. Response-Level Features (Infrastructure)

| Feature | Type | Source Logic | Wireshark Filter / Verification |
| :--- | :--- | :--- | :--- |
| **`dns_answer_count`**| **Direct** | Number of actual Answer records processed (loop count). | Count the number of "Answer" lines in the "Domain Name System (response)" tree in Wireshark. |
| **`dns_answer_rrtypes`**|**Direct**| Count of *unique* record types (A, AAAA, CNAME) in answers. | `dns.resp.type`. Check how many distinct types exist in the response section. |
| **`dns_answer_ttls_mean`**|**Derived**| Average of all TTL values found in all Answer records. | `dns.resp.ttl`. Extract all TTLs -> Sum them -> Divide by count. |
| **`dns_answer_ttls_max`**|**Derived**| The highest TTL value found. | Sort `dns.resp.ttl` column in Wireshark descending. Top value. |
| **`dns_answer_ttls_min`**|**Derived**| The lowest TTL value found. | Sort `dns.resp.ttl` column ascending. Bottom value. |

---

## 4. Derived & Advanced Features (Behavioral)

These features are calculated by aggregating multiple packets. They are not found in a single field but describe the flow's behavior.

| Feature | Type | Source Logic | Wireshark Verification Strategy |
| :--- | :--- | :--- | :--- |
| **`dns_total_queries`** | **Derived** | Count of packets where `QR=0`. | Filter `dns.flags.response == 0`. Count packets in the flow. |
| **`dns_total_responses`**| **Derived** | Count of packets where `QR=1`. | Filter `dns.flags.response == 1`. Count packets in the flow. |
| **`dns_unique_domains`** | **Derived** | Size of a Set containing all unique `QNAME` strings seen. | Filter `dns.qry.name`. Go to Statistics -> DNS -> Tree. Count distinct names. |
| **`dns_rrtype_entropy`** | **Derived** | Shannon entropy of the distribution of Query Types. | Hard to manually calculate. Check if types are uniform (high entropy) or single-type (zero entropy). |

---

## 5. Rate & Temporal Features (Flooding/DoS)

| Feature | Type | Source Logic | Wireshark Verification Strategy |
| :--- | :--- | :--- | :--- |
| **`queries_per_second`** | **Derived** | `total_queries` / `flow_duration_seconds`. | (Count of `dns.flags.response == 0`) / (Time of Last Packet - Time of First Packet). |
| **`nxdomain_rate`** | **Derived** | `count(NXDOMAIN)` / `total_responses`. | Filter `dns.flags.rcode == 3`. Count packets. Divide by total response count. |

---

## 6. Size & EDNS (Tunneling/Amplification)

| Feature | Type | Source Logic | Wireshark Filter / Verification |
| :--- | :--- | :--- | :--- |
| **`dns_edns_present`** | **Direct** | 1 if an OPT Record (Type 41) is found in Additional Section. | Filter `dns.resp.type == 41` or look for "OPT" in Additional records. |
| **`dns_edns_udp_size`**| **Direct** | Reads the "UDP Payload Size" field from the OPT record. | `dns.rr.udp_payload_size`. |
| **`dns_response_size`**| **Derived**| Sum of packet lengths for all response packets. | Filter `dns.flags.response == 1`. Sum the `frame.len` or `udp.length` column. |
