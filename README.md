# Enhanced Network Traffic Analyzer (CICFlowMeter + DNS DPI)

## 1. About The Tool
This application is a robust **Network Flow Generator** and **Traffic Analyzer** written in Java. It is designed to inspect network traffic in real-time or from saved files (PCAP) and extract meaningful statistical features for Machine Learning and Cyber Security analysis.

Unlike standard flow exporters that only look at "headers" (Layer 3/4), this tool includes a specialized **Deep Packet Inspection (DPI)** engine for **DNS (Domain Name System)** traffic, enabling the detection of sophisticated attacks like DNS Tunneling, Amplification, and DGA Botnets.

---

## 2. Comparison: Enhanced vs. Legacy CICFlowMeter
> [!NOTE]
> For a detailed line-by-line comparison, see our [Comprehensive Differences Guide](DIFFERENCES.md).
> 
| Feature | Legacy CICFlowMeter | **Enhanced Version (This Tool)** |
| :--- | :--- | :--- |
| **Flow Definition** | Standard 5-Tuple | Standard 5-Tuple (Identical Logic) |
| **Statistical Features** | ~80 Features (IAT, Sizes, Idle/Active) | Replicates Core Stats + **30+ New DNS Features** |
| **DNS Visibility** | None (treats DNS as generic UDP) | **Full DPI**: Inspects Queries, Answers, TTLs, Entropy |
| **Architecture** | JNetPcap (Older, Native issues) | **Pcap4J** (Modern, Better Java integration) |
| **Stability** | Known for crashing on malformed packets | **Robust Error Handling** & Graceful Shutdown Hooks |
| **Java Version** | Legacy Java | Compatible with Java 8 through 17+ |

---

## 3. Technology Stack
*   **Language**: Java 8 (Compatible with modern JVMs).
*   **Build System**: Apache Maven.
*   **Packet Capture Library**: `Pcap4J` (Wrapper for `libpcap`/`Npcap`).
*   **Math Library**: `Apache Commons Math 3` (For Statistical calculations).
*   **Packet Parsing**: Native `Pcap4J` packet decoding.

---

## 4. How It Works (Architecture)

### The "Flow" Concept
A "Flow" is defined as a bidirectional conversation between two points. We identify it using a **5-Tuple Key**:
1.  **Source IP**
2.  **Destination IP**
3.  **Source Port**
4.  **Destination Port**
5.  **Protocol** (TCP/UDP)

### The Pipeline
1.  **Ingestion**: Packets are captured from the Network Card (`eth0`) or File (`.pcap`) raw bytes.
2.  **Decoding**: Bytes are converted into Java Objects (`IpV4Packet`, `UdpPacket`).
3.  **Aggregation**: The main engine searches for an existing `Flow` conversation.
    *   *Match found*: Add this packet's size/time to the existing stats.
    *   *No match*: Create a new conversation.
4.  **Deep Inspection**: If the port is **53** (DNS), the payload is sent to the `DnsFeatureExtractor` to parse the specific Query/Response details.
5.  **Export**: When a conversation finishes (Timeout of 120s or Shutdown), it is written as a Row in the CSV file.

---

## 5. Extracted Features (The CSV Output)

### Standard Traffic Features (The "Shape" of traffic)
*   **Flow Duration**: How long the conversation lasted.
*   **Packet Counts**: Total Forward (Src->Dst) and Backward (Dst->Src) packets.
*   **Length Statistics**: Mean, Max, and StdDev of packet sizes.
*   **IAT (Inter-Arrival Time)**: The silent time between packets. Important for detecting "beacons" (C2 servers).

### DNS Infrastructure Features (Abuse Detection)
> [!TIP]
> See [FEATURES_DOCUMENTATION.md](FEATURES_DOCUMENTATION.md) for a full definition of every feature and how it is derived.
> **Understanding Attacks**: See [ATTACK_EXPLANATION.md](ATTACK_EXPLANATION.md) to learn how attackers usage DNS vs DoH.
>
> **Checklist**: See [REQUIRED_ATTACKS_LIST.md](REQUIRED_ATTACKS_LIST.md) for the 5 infrastructure attacks you must include in your dataset.
>
> **How It Works**: See [FEATURE_EXTRACTION_EXPLAINED.md](FEATURE_EXTRACTION_EXPLAINED.md) to understand the difference between Network Flows and DNS Packets.
*   **Volume & Flag Analysis**:
    *   `Queries/Sec`: #1 Indicator for floods.
    *   `DNS Amp Factor`: Measures effective amplification (Bytes Out > Bytes In).
    *   `Query/Response Ratio`: Asymmetry detection (1000 Queries vs 0 Responses).
*   **Intent Analysis**:
    *   `ANY/TXT Ratios`: Attackers use specific record types for payload maximization.
    *   `EDNS Size`: Requesting 4096 bytes indicates intended amplification.
*   **Signature Analysis**:
    *   `Packet StdDev`: Automated tools send uniform packet sizes (StdDev=0).
    *   `OpCode/RCode`: Detecting rare protocol exploits (Update/Notify).

---

## 6. Development Process & Implementation
1.  **Requirement Analysis**: We analyzed the need for DNS visibility missing in the old tool.
2.  **Architecture Design**: We chose `Pcap4J` for modern compatibility and designed a modular `DnsFeatureExtractor` class to isolate the complex parsing logic from the main Flow engine.
3.  **Core Logic**: Re-implemented the 5-tuple Map system to track millions of concurrent flows efficiently.
4.  **Verification**: We built a synthetic PCAP generator to prove that if a packet contains "example.com", the tool correctly reports "QD Count=1".

---

## 7. User Guide

### Prerequisites
*   **Java Runtime**: JRE 8 or higher.
*   **Admin Privileges**: `sudo` access is required for live capture.
*   **OS**: Linux (tested), Windows/Mac (supported with Npcap/libpcap).

### Running the Tool

#### 1. Live Capture (Real-Time)
Monitor your network interface (`eth0`, `wlan0`, etc.).
```bash
sudo java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -i eth0 -o live_capture.csv
```
*   **Stop**: Press **Ctrl+C**. The tool will save all data before exiting.

#### 2. Offline Analysis (Forensic)
Read a saved capture file.
```bash
java -jar net-traffic-analysis-1.0-SNAPSHOT.jar -f suspicious_traffic.pcap -o forensics_report.csv
```

---

## 8. Reliability & Troubleshooting

### Is it Reliable?
**Yes.** It uses **libpcap** (the engine behind Wireshark).
*   To verify: Run Wireshark alongside this tool. Check if the "Question Count" in Wireshark matches the `DNS QD Count` in the CSV. They will be identical.
*   **Deep Dive**: See our [Wireshark Testing & Verification Guide](WIRESHARK_TESTING_GUIDE.md) for a field-by-field breakdown.

### Using for Machine Learning
> [!TIP]
> See [FEATURE_ENGINEERING_TIPS.md](FEATURE_ENGINEERING_TIPS.md) for a guide on Data Cleaning, Scaling, and Encoding before training your model.
> **Walkthrough**: See [FEATURE_ENGINEERING_WALKTHROUGH.md](FEATURE_ENGINEERING_WALKTHROUGH.md) for a real-world example with sample data.
> **Data Dictionary**: See [METRICS_AND_UNITS.md](METRICS_AND_UNITS.md) for a definition of every CSV column's unit and formula.

### Common Errors
1.  **"Operation Not Permitted"**:
    *   *Cause*: You didn't use `sudo`.
    *   *Fix*: Run `sudo java -jar ...`
2.  **"Interface Not Found"**:
    *   *Cause*: You typed the wrong name (e.g., `eth0` when it's `ens33`).
    *   *Fix*: Run `ip addr` to check your interface names.
