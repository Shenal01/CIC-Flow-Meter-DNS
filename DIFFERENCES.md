# Comparison: Antigravity (Enhanced CICFlowMeter) vs. Legacy CICFlowMeter

This document outlines the key differences between the original [CICFlowMeter](https://github.com/UNBCIC/CICFlowMeter) developed by the Canadian Institute for Cybersecurity (CIC) and this enhanced version ("Antigravity").

## Executive Summary

**Antigravity** is a modern fork and enhancement of the original tool. While it preserves the core logic for calculating standard flow statistics (making it compatible with existing datasets like CICIDS2017), it completely replaces the underlying packet capture engine and adds a new **Deep Packet Inspection (DPI)** layer specifically for DNS traffic.

| Feature | Legacy CICFlowMeter | Antigravity (Enhanced) |
| :--- | :--- | :--- |
| **Status** | Archived / Legacy (Last major update ~2018) | Active Development |
| **Packet Engine** | `jnetpcap` (Requires complex native setup) | `Pcap4J` (Modern, Standardized) |
| **Java Support** | Java 7/8 (Issues with newer JVMs) | Java 11 / 17+ Compatible |
| **DNS Features** | **0** (Treats DNS as generic UDP) | **30+** (Query Types, TTLs, Entropy, etc.) |
| **Stability** | Known issues with malformed packets | Enhanced Error Handling & Graceful Shutdown |

---

## 1. Architectural Changes

### The Move from JNetPcap to Pcap4J
The most significant "under the hood" change is the migration from `jnetpcap` to `Pcap4J`.
*   **Legacy (JNetPcap)**: Relied on an older wrapper around libpcap that often required manually placing `.so` or `.dll` files in system directories. It frequently suffered from compatibility issues on modern Linux kernels and Windows versions.
*   **Enhanced (Pcap4J)**: Uses a broadly supported, accessible library that integrates cleaner with modern Maven builds and handles native resource management more reliably.

### Modular DPI Engine
The original tool was a monolith focused on Layer 3 (IP) and Layer 4 (TCP/UDP) headers.
*   **Antigravity** introduces a pluggable architecture where flows can be passed to "Feature Extractors".
*   Currently, a **DNS Feature Extractor** is implemented, which parses the *payload* of port 53 traffic to extract application-layer data.

---

## 2. Feature Set Comparison

### Standard Traffic Features (Shared)
Both tools calculate the standard ~80 flow features used in cybersecurity research, including:
*   **Time-based**: Flow Duration, Inter-Arrival Times (IAT).
*   **Size-based**: Packet lengths (Min, Max, Mean, StdDev).
*   **Flag-based**: TCP Flags (SYN, FIN, RST, etc.).

*Result: If you run both tools on a generic HTTP pcap, the output for these columns will be nearly identical.*

### New DNS-Specific Features (Antigravity Only)
The legacy tool produces **no specific columns** for DNS details. Antigravity adds over 30 new columns to the CSV output specifically for DNS analysis:

#### Header Information
*   `dns_query_count`: Number of questions in the flow.
*   `dns_answer_count`: Number of answer records.
*   `dns_authority_count`: Number of authority records.
*   `dns_additional_count`: Number of additional records.

#### Content Analysis (DPI)
*   `dns_query_len`: Length of the requested domain name (critical for detecting DNS Tunneling).
*   `dns_query_type`: Statistics on the types of queries (A, AAAA, TXT, etc.).
*   `dns_rcode`: Response codes (e.g., NXDOMAIN for DGA botnet detection).

#### Advanced Forensics
*   `dns_ttl_mean`: Average Time-To-Live. (Low TTL is a hallmark of "Fast Flux" botnet networks).
*   `dns_entropy`: Mathematical entropy of the domain strings (High entropy indicates encrypted payloads tunneling through DNS).

---

## 3. Usability Improvements

*   **Command Line Interface**: The argument parsing has been cleaned up to be more robust.
*   **Console Output**: Antigravity provides clearer, real-time logging of the capture status.
*   **Build System**: The Maven configuration is updated to handle dependencies automatically without manual local repository installations (which were required for the old `jnetpcap` artifact).
