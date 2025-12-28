package com.antigravity.traffic;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DnsRCode;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.util.HashSet;
import java.util.Set;

/**
 * Extracts Deep Packet Inspection (DPI) features for DNS traffic.
 * Refactored for Infrastructure Abuse & DDoS detection.
 */
public class DnsFeatureExtractor {

    // A. Header-Level
    private boolean isDns = false;
    private long dnsQrQueryCount = 0;
    private long dnsQrResponseCount = 0;
    private int lastOpCode = -1;

    // Aggregate counts across all packets in flow (Header fields)
    private long totalQdCount = 0;
    private long totalAnCount = 0; // Cumulative Answer Count from Header

    // B. Query-Level
    private int lastQueryType = -1;

    // C. Infrastructure Specific Counts
    private long dnsAnyCount = 0; // Amplification
    private long dnsTxtCount = 0; // Amplification

    // D. Size & Volumetrics
    private long totalQueryBytes = 0;
    private long totalResponseBytes = 0;
    private double packetSizeSqSum = 0;

    // E. EDNS
    private boolean hasEdns = false;
    private int ednsUdpSize = 0;

    public void processPacket(Packet payload, int length) {
        if (payload == null)
            return;

        // Try to parse as DNS
        if (!payload.contains(DnsPacket.class)) {
            return;
        }

        DnsPacket dnsPacket = payload.get(DnsPacket.class);
        if (dnsPacket == null)
            return;

        DnsPacket.DnsHeader header = dnsPacket.getHeader();
        if (header == null)
            return;

        isDns = true;

        // 1. Header Parsing
        boolean isResponse = header.isResponse();
        if (isResponse) {
            dnsQrResponseCount++;
            totalResponseBytes += length;
        } else {
            dnsQrQueryCount++;
            totalQueryBytes += length;
        }

        // StdDev Calculation Helper
        packetSizeSqSum += (double) length * length;

        lastOpCode = (int) header.getOpCode().value();

        totalQdCount += header.getQdCountAsInt();
        totalAnCount += header.getAnCountAsInt();

        // 2. EDNS Check
        for (DnsResourceRecord rr : header.getAdditionalInfo()) {
            if (rr.getDataType() == DnsResourceRecordType.OPT) {
                hasEdns = true;
                ednsUdpSize = rr.getDataClass().value() & 0xFFFF;
            }
        }

        // 3. Query Parsing (Questions)
        for (DnsQuestion q : header.getQuestions()) {
            int qType = (int) q.getQType().value();
            lastQueryType = qType;

            // Check for Amplification Types (ANY=255, TXT=16)
            if (qType == 255) { // ANY
                dnsAnyCount++;
            } else if (qType == 16) { // TXT
                dnsTxtCount++;
            }
        }
    }

    // Getters for Features

    public boolean isDnsFlow() {
        return isDns;
    }

    // --- Direct Features ---

    public int getDnsQr() {
        // Return 1 if we saw any response (completed interaction), else 0
        return (dnsQrResponseCount > 0) ? 1 : 0;
    }

    public int getDnsOpCode() {
        return lastOpCode == -1 ? 0 : lastOpCode;
    }

    public long getDnsQdCount() {
        return totalQdCount;
    }

    public int getDnsQueryType() {
        return lastQueryType == -1 ? 0 : lastQueryType;
    }

    public long getDnsAnswerCount() {
        return totalAnCount;
    }

    public int getDnsEdnsPresent() {
        return hasEdns ? 1 : 0;
    }

    public int getDnsEdnsUdpSize() {
        return ednsUdpSize;
    }

    // --- Derived Infrastructure Features ---

    public long getDnsTotalQueries() {
        return dnsQrQueryCount;
    }

    public long getDnsTotalResponses() {
        return dnsQrResponseCount;
    }

    public double getQueriesPerSecond(double durationSec) {
        if (durationSec <= 0)
            return 0.0;
        return dnsQrQueryCount / durationSec;
    }

    public long getDnsResponseSize() {
        return totalResponseBytes;
    }

    /**
     * Amplification Factor = Avg Response Size / Avg Query Size
     * If no queries/responses, returns 0.
     */
    public double getDnsAmplificationFactor() {
        if (dnsQrQueryCount == 0 || dnsQrResponseCount == 0)
            return 0.0;
        double avgQuery = (double) totalQueryBytes / dnsQrQueryCount;
        double avgResp = (double) totalResponseBytes / dnsQrResponseCount;
        if (avgQuery == 0)
            return 0.0;
        return avgResp / avgQuery;
    }

    /**
     * Ratio of Queries to Responses.
     * High ratio (> 10) indicates Query Flood / Water Torture.
     */
    public double getQueryResponseRatio() {
        if (dnsQrResponseCount == 0)
            return dnsQrQueryCount; // Infinite/High
        return (double) dnsQrQueryCount / dnsQrResponseCount;
    }

    /**
     * Standard Deviation of Packet Sizes in this flow.
     */
    public double getPacketSizeStdDev() {
        long totalCount = dnsQrQueryCount + dnsQrResponseCount;
        if (totalCount <= 1)
            return 0.0;

        long totalBytes = totalQueryBytes + totalResponseBytes;
        double mean = (double) totalBytes / totalCount;
        double variance = (packetSizeSqSum / totalCount) - (mean * mean);

        return (variance > 0) ? Math.sqrt(variance) : 0.0;
    }

    public double getDnsAnyQueryRatio() {
        if (dnsQrQueryCount == 0)
            return 0.0;
        return (double) dnsAnyCount / dnsQrQueryCount;
    }

    public double getDnsTxtQueryRatio() {
        if (dnsQrQueryCount == 0)
            return 0.0;
        return (double) dnsTxtCount / dnsQrQueryCount;
    }
}
