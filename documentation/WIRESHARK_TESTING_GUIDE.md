# Wireshark & CSV Verification Guide (Manual Audit)

This guide serves as the **Standard Operating Procedure (SOP)** for verifying that the tool's CSV output is accurate using Wireshark.

**Prerequisites**:
1.  Open your **PCAP file** in Wireshark.
2.  Open your **CSV file** in Excel/Sheets.

---

## Phase 1: Locating the Flow

To verify a feature, you must first look at the *exact same packets* that the tool analyzed.

### Step 1: Pick a Row
Select a row in your CSV that looks interesting (e.g., has `Total Queries > 1` or `Amp Factor > 1`).

*Example CSV Row:*
```csv
Src IP,Dst IP,Src Port,Dst Port,Protocol,...
192.168.137.199,192.168.137.1,58618,53,17,...
```

### Step 2: Build the Filter
In the top bar of Wireshark, type a filter that matches the **5-Tuple** from your CSV row.

**Formula**:
```text
ip.addr == [Src IP] && ip.addr == [Dst IP] && udp.port == [Src Port] && udp.port == [Dst Port]
```

**Example Filter**:
```text
ip.addr == 192.168.137.199 && ip.addr == 192.168.137.1 && udp.port == 58618 && udp.port == 53
```
*Tip: If Protocol is TCP, use `tcp.port` instead of `udp.port`.*

**Result**: Wireshark should show only the packets for that specific conversation.

---

## Phase 2: Verifying Columns (Step-by-Step)

Go through the columns in your CSV row and check them against the Wireshark view.

### A. Basic Identification
| CSV Column | Wireshark Check |
| :--- | :--- |
| **Flow Duration** | Look at the "Time" column. `Last Packet Time - First Packet Time`. |
| **Tot Fwd/Bwd Pkts** | Count the packets taking into account direction. |

### B. DNS Header Flags (Direct)
*Look at the "Domain Name System" section in the packet details pane.*

| CSV Column | Wireshark Field | How to Verify |
| :--- | :--- | :--- |
| **dns_qr** | `Flags` -> `Response` | **0** if it's a Query, **1** if it's a Response. |
| **dns_opcode** | `Flags` -> `Opcode` | Check the value (e.g., "Standard query (0)"). |
| **dns_qdcount** | `Questions` | Count the number of items in the "Questions" section. |
| **dns_query_type** | `Queries` -> `Type` | Check if it says `A (1)`, `AAAA (28)`, `TXT (16)`, or `ANY (255)`. |
| **dns_answer_count** | `Answer RRs` | Count of items in the "Answers" section. |

### C. Volume Metrics (Direct Count)

| CSV Column | Verification Method |
| :--- | :--- |
| **dns_total_queries** | Count how many **Blue** (Query) packets are in the filtered view. |
| **dns_total_responses** | Count how many **Yellow** (Response) packets are in the filtered view. |
| **queries_per_second** | `Total Queries` / `Flow Duration (Seconds)`. |

### D. Advanced Math Features (Calculator Needed)

These features detect Abuse and must be calculated manually.

#### 1. `dns_amplification_factor`
*   **Concept**: How much bigger is the response than the query?
*   **Verification**:
    1.  Click the **Query Packet**. look at `Length` column (e.g., 60).
    2.  Click the **Response Packet**. look at `Length` column (e.g., 3000).
    3.  **Calculate**: `3000 / 60` = **50.0**.
    4.  **Check CSV**: Matches?

#### 2. `query_response_ratio`
*   **Concept**: Are we sending more queries than we get back?
*   **Verification**:
    1.  Count Queries (e.g., 5).
    2.  Count Responses (e.g., 5).
    3.  **Calculate**: `5 / 5` = **1.0**.
    4.  **Check CSV**: Matches?

#### 3. `packet_size_stddev`
*   **Concept**: Are the packet sizes varying (Human) or identical (Bot)?
*   **Verification**:
    1.  Write down the `Length` of every packet in the flow: e.g., `[60, 60, 60, 60]`.
    2.  **Calculate**: If they are all identical, StdDev must be **0.0**.
    *   **Note**: The tool uses **Population StdDev** (N). Some online calculators use **Sample StdDev** (N-1). If numbers differ slightly, check your formula.
    3.  **Check CSV**: Matches?

#### 4. `dns_any_query_ratio`
*   **Concept**: What % of requests are for `ANY` records?
*   **Verification**:
    1.  Count packets where `Type` is `ANY` (e.g., 90).
    2.  Count total queries (e.g., 100).
    3.  **Calculate**: `90 / 100` = **0.9**.
    4.  **Check CSV**: Matches?

---

## Phase 3: "Trust" Clean Check
If you check 3-5 random flows using this method and the numbers match, the tool is mathematically verified.
