# Features Documentation (Master Reference)

This document is the **Single Source of Truth** for the 30 features (columns) extracted by the tool.
It defines **Why** we need each feature (Importance), **How** it is retrieved (Extraction), and **Math** behind it (Calculation).

---

## 1. Network Identifiers (The "5-Tuple")
*These define "Who" is talking.*

| Feature | Importance (Why?) | Extraction (How?) | Calculation / Logic |
| :--- | :--- | :--- | :--- |
| **Src IP** | Identifies the attacking machine or victim. | `IP Header -> Source Address` | N/A (Direct Extraction) |
| **Dst IP** | Identifies the target server or victim. | `IP Header -> Destination Address` | N/A (Direct Extraction) |
| **Src Port** | High ports (>1024) usually imply clients; Port 53 implies server. | `UDP/TCP Header -> Source Port` | N/A (Direct Extraction) |
| **Dst Port** | Targeted service (53=DNS, 80=HTTP). | `UDP/TCP Header -> Dest Port` | N/A (Direct Extraction) |
| **Protocol** | Distinguishes UDP (Connectionless) vs TCP (Connection). | `IP Header -> Protocol` (6 or 17) | N/A (Direct Extraction) |

---

## 2. Basic Flow Stats (Time & Length)
*These measure the "Shape" and "Duration" of the conversation.*

| Feature | Importance (Why?) | Extraction (How?) | Calculation / Logic |
| :--- | :--- | :--- | :--- |
| **Flow Duration** | Long duration + High Volume = Sustained Flood. | Time differences of packets. | `LastPacket_Time - FirstPacket_Time` (ms) |
| **Tot Fwd Pkts** | Measures traffic volume Outbound (Attacker -> Server). | Counter in Flow Object. | `Count(Packets)` where Source == Flow Initiator. |
| **Tot Bwd Pkts** | Measures traffic volume Inbound (Server -> Attacker). | Counter in Flow Object. | `Count(Packets)` where Source == Flow Target. |
| **Flow Len Mean** | Average packet size. Small (60B) = TCP SYN Flood. | Packet Lengths. | `Sum(All_Packet_Lengths) / Total_Packets` |
| **Flow Len Std** | **CRITICAL**: Detects Botnets. Bots act uniformly (Std=0); Humans vary. | Packet Lengths. | `Population_StdDev(All_Packet_Lengths)` |
| **Flow Len Max** | Detects large payloads (Amplification responses). | Packet Lengths. | `Max(All_Packet_Lengths)` |
| **Flow IAT Mean** | Inter-Arrival Time. Low IAT = High Speed/High Rate flood. | Timestamp Diffs. | `Mean(Time_Diff(Packet_i, Packet_i-1))` |
| **Flow IAT Std** | Jitter. Automated floods have constant IAT (Low Std). | Timestamp Diffs. | `Population_StdDev(IAT_Values)` |
| **Flow IAT Max** | Detects "Bursty" attacks (Wait... then Flood). | Timestamp Diffs. | `Max(IAT_Values)` |

---

## 3. DNS Header Features (Direct)
*Specific fields from the DNS Protocol Header.*

| Feature | Importance (Why?) | Extraction (How?) | Calculation / Logic |
| :--- | :--- | :--- | :--- |
| **dns_qr** | Query (0) vs Response (1). Distinguishes "Flooder" vs "Victim". | `DNS Header -> QR Bit` | `0` if Query, `1` if Response. |
| **dns_opcode** | Rare Opcodes (Update/Notify) indicate Server Exploit attempts. | `DNS Header -> Opcode` | Bits 11-14 of Flags. |
| **dns_qdcount** | Malformed packets often have 0 or >100 questions to crash parsers. | `DNS Header -> QDCOUNT` | 16-bit Integer Value. |
| **dns_query_type** | `ANY` (255) and `TXT` (16) are used for Amplification. | `First Question -> QTYPE` | 16-bit Integer Value. |
| **dns_answer_count** | High answer counts indicate Reflection Attacks. | `DNS Header -> ANCOUNT` | 16-bit Integer Value. |

---

## 4. DNS Volume & Rate
*Aggregated metrics specific to DNS traffic.*

| Feature | Importance (Why?) | Extraction (How?) | Calculation / Logic |
| :--- | :--- | :--- | :--- |
| **dns_total_queries** | High volume of simple queries = Query Flood (Water Torture). | DPI counter. | `Count(Packets)` where `QR == 0`. |
| **dns_total_responses** | High volume of responses = Reflection Attack Victim. | DPI counter. | `Count(Packets)` where `QR == 1`. |
| **queries_per_second** | **CORE METRIC**: The definition of a flood (e.g., >1000 QPS). | Computed. | `dns_total_queries / (Duration_ms / 1000.0)` |

---

## 5. Size & EDNS (Payload)
*Advanced DNS features used in modern Amplification attacks.*

| Feature | Importance (Why?) | Extraction (How?) | Calculation / Logic |
| :--- | :--- | :--- | :--- |
| **dns_edns_present** | Amplification requires EDNS to ask for >512 bytes. | `Additional Record -> Type 41` | `1` if OPT record exists, else `0`. |
| **dns_edns_udp_size** | Attackers explicit ask for max buffer (4096) to maximize damage. | `OPT Record -> Class Field` | Integer Value (payload size). |
| **dns_response_size** | Measures actual bandwidth impact (Saturation). | Packet Lengths. | `Sum(Lengths)` where `QR == 1`. |

---

## 6. Infrastructure & Abuse Ratios (Derived)
*The "Intelligence" layer. These combine other features to reveal intent.*

| Feature | Importance (Why?) | Extraction (How?) | Calculation / Logic |
| :--- | :--- | :--- | :--- |
| **dns_amplification_factor** | **Efficiency**: Is the attacker getting free bandwidth? (>10.0 is Bad). | Computed. | `Avg(Resp Bytes) / Avg(Query Bytes)` |
| **query_response_ratio** | **Asymmetry**: Query Floods have high Queries/Low Responses. | Computed. | `Total Queries / Total Responses` |
| **packet_size_stddev** | **Bot Detection**: Automated tools send identical packets (StdDev = 0). | Computed. | `Population_StdDev(All_Packet_Lengths)` |
| **dns_any_query_ratio** | **Intent**: `ANY` queries are deprecated. Usage = Malicious. | Computed. | `Count(QTYPE==255) / Total_Queries` |
| **dns_txt_query_ratio** | **Payload**: `TXT` records store large strings for amplification. | Computed. | `Count(QTYPE==16) / Total_Queries` |
