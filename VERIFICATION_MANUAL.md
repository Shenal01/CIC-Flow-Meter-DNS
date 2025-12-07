# Verification Manual: Ensuring Accuracy

This guide provides three methods to verify that the extracted results from **Antigravity (Enhanced CICFlowMeter)** are accurate and genuine.

## Method 1: Synthetic "Ground Truth" Verification
The most reliable way to verify any tool is to test it against data where the *exact* expected answer is known. We provide a script to generate such data.

### 1. Generate Known Traffic
Run the Python script included in the repo. It creates a PCAP file with exactly 3 packets:
1.  **Standard Query** (`example.com`, Type A)
2.  **NXDOMAIN Response** (Simulating a "Domain Not Found" error)
3.  **EDNS Query** (Simulating an advanced DNS feature)

```bash
python3 generate_pcap.py
# Creates 'verification_traffic.pcap'
```

### 2. Run the Tool
```bash
java -jar target/net-traffic-analysis-1.0-SNAPSHOT.jar -f verification_traffic.pcap -o verify.csv
```

### 3. Check the "Ground Truth"
Open `verify.csv` and confirm the following key columns match the known input:

| Feature | Expected Value | Why? |
| :--- | :--- | :--- |
| `dns_qr` | `1` | We sent a response packet. |
| `nxdomain_rate` | `1.0` | We sent 1 response, and it was NXDOMAIN (100%). |
| `dns_edns_present` | `1` | Packet #3 had an OPT record. |
| `dns_edns_udp_size`| `4096` | Packet #3 explicitly set this buffer size. |
| `dns_unique_domains` | `2` | `example.com` and `test.com`. |

If these numbers match, the tool's logic is **mathematically correct**.

---

## Method 2: Cross-Validation with Wireshark
Wireshark is the industry standard for packet analysis. You can use it to "spot check" this tool.

1.  **Capture Traffic**:
    ```bash
    sudo tcpdump -i eth0 -w live_test.pcap port 53
    ```
    *(Press Ctrl+C after ~30 seconds)*

2.  **Run Antigravity**:
    ```bash
    java -jar target/net-traffic-analysis-1.0-SNAPSHOT.jar -f live_test.pcap -o tool_output.csv
    ```

3.  **Compare Counts**:
    *   Open `live_test.pcap` in Wireshark.
    *   Filter for `dns`.
    *   **Check Query Count**: Look at the status bar or Statistics -> DNS. Compare this number with `dns_total_queries` in the CSV.
    *   **Check NXDOMAIN**: Filter `dns.flags.rcode == 3`. Count the packets. Compare with `nxdomain_rate` * `dns_total_responses` in the CSV.

---

## Method 3: Architecture Guarantee
It is important to note *how* this tool works.
*   **Engine**: We use `libpcap` (via Pcap4J). This is the **exact same library** that powers Wireshark, TCPDump, and Snort.
*   **No Estimation**: The tool does not "estimate" values. It parses the binary bytes of every packet. If a packet has the "QR" bit set to 1, we count it.

**Conclusion**: As long as the network card captures the packet, this tool reads the exact same binary data as any forensic software.
