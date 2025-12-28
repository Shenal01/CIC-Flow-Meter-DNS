# Metrics & Units Reference

This document lists every column in the generated CSV, defining its **Unit**, **Data Type**, and the **Exact Extraction Logic/Formula** used by the tool.

## 1. Network Identifiers (5-Tuple)
| Column | Unit | Data Type | Extraction Logic / Source | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Src IP** | N/A | String | `IP Header -> Source Address` | Source IP Address. |
| **Dst IP** | N/A | String | `IP Header -> Destination Address` | Destination IP Address. |
| **Src Port** | Number | Integer | `UDP/TCP Header -> Source Port` | Source Port. |
| **Dst Port** | Number | Integer | `UDP/TCP Header -> Destination Port` | Destination Port. |
| **Protocol** | N/A | String | `IP Header -> Protocol Field` | Transport Protocol (UDP=17, TCP=6). |

## 2. Basic Flow Stats (Time & Length)
| Column | Unit | Data Type | Extraction Logic / Formula | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Flow Duration** | ms | Long | `LastPacket.Time - FirstPacket.Time` | Total duration of the flow. |
| **Tot Fwd Pkts** | Count | Long | `Count(Packets)` where `SrcIP == Flow.SrcIP` | Total packets sent forward. |
| **Tot Bwd Pkts** | Count | Long | `Count(Packets)` where `SrcIP == Flow.DstIP` | Total packets sent backward. |
| **Flow Len Mean** | Bytes | Double | `Sum(Packet.Length) / Count(Packets)` | Average wire length of all packets. |
| **Flow Len Std** | Bytes | Double | `Population_StdDev(Packet.Lengths)` | Standard Deviation of packet lengths. |
| **Flow Len Max** | Bytes | Integer | `Max(Packet.Lengths)` | Largest packet size observed. |
| **Flow IAT Mean** | ms | Double | `Mean(Time_Diff(Packet_i, Packet_i-1))` | Average time between packets. |
| **Flow IAT Std** | ms | Double | `Population_StdDev(IATs)` | Standard deviation of inter-arrival times. |
| **Flow IAT Max** | ms | Long | `Max(IATs)` | Longest single silence period. |

## 3. DNS Header Features (Direct)
| Column | Unit | Data Type | Extraction Logic / Formula | Description |
| :--- | :--- | :--- | :--- | :--- |
| **dns_qr** | Flag | Integer | `DNS Header -> QR Flag` (Bit 16) | 0=Query, 1=Response. |
| **dns_opcode** | ID | Integer | `DNS Header -> Opcode` (Bits 11-14) | Operation Code (0=Standard). |
| **dns_qdcount** | Count | Integer | `DNS Header -> QDCOUNT` (16 bits) | Number of Questions. |
| **dns_query_type** | ID | Integer | `First Question -> QTYPE` (16 bits) | Type of the last/first query seen. |
| **dns_answer_count** | Count | Integer | `DNS Header -> ANCOUNT` (16 bits) | Number of Answer Records. |

## 4. DNS Volume & Rate
| Column | Unit | Data Type | Extraction Logic / Formula | Description |
| :--- | :--- | :--- | :--- | :--- |
| **dns_total_queries** | Count | Integer | `Count(Packets)` where `DNS.QR == 0` | Total Query packets. |
| **dns_total_responses** | Count | Integer | `Count(Packets)` where `DNS.QR == 1` | Total Response packets. |
| **queries_per_second** | Hz | Double | `dns_total_queries / (Flow Duration / 1000.0)` | Rate of queries per second. |

## 5. Size & EDNS (Payload)
| Column | Unit | Data Type | Extraction Logic / Formula | Description |
| :--- | :--- | :--- | :--- | :--- |
| **dns_edns_present** | Flag | Integer | `1` if `AdditionalRecord.Type == OPT` exists | EDNS usage flag. |
| **dns_edns_udp_size** | Bytes | Integer | `OPT Record -> CLASS Field` | Max UDP buffer size requested. |
| **dns_response_size** | Bytes | Long | `Sum(Packet.Length)` where `DNS.QR == 1` | Total bytes of all response packets. |

## 6. Infrastructure & Abuse Ratios (Derived)
| Column | Unit | Data Type | Extraction Logic / Formula | Description |
| :--- | :--- | :--- | :--- | :--- |
| **dns_amplification_factor** | Ratio | Double | `Avg(Resp Bytes) / Avg(Query Bytes)` | Amplification efficiency. |
| **query_response_ratio** | Ratio | Double | `dns_total_queries / dns_total_responses` | Asymmetry of the flow. |
| **packet_size_stddev** | Bytes | Double | `Population_StdDev(All_Packet_Lengths)` | Uniformity metric (0 = Bot). |
| **dns_any_query_ratio** | Ratio | Double | `Count(QTYPE==255) / dns_total_queries` | Ratio of ANY queries. |
| **dns_txt_query_ratio** | Ratio | Double | `Count(QTYPE==16) / dns_total_queries` | Ratio of TXT queries. |
