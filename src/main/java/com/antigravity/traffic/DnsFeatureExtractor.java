package com.antigravity.traffic;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DnsOpCode;
import org.pcap4j.packet.namednumber.DnsRCode;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

/**
 * Extracts Deep Packet Inspection (DPI) features for DNS traffic.
 */
public class DnsFeatureExtractor {

    // A. Header-Level
    private boolean isDns = false;
    private long dnsQrQueryCount = 0;
    private long dnsQrResponseCount = 0;
    // Storing last observed OpCode/RCode for simple CSV representation (or could be
    // majority)
    private int lastOpCode = -1;
    private int lastRCode = -1;

    // Aggregate counts across all packets in flow
    private long totalQdCount = 0;
    private long totalAnCount = 0;
    private long totalNsCount = 0;
    private long totalArCount = 0;

    // B. Query-Level
    private long totalQueryLength = 0;
    private long queryCount = 0;
    // For type, we can store the most frequent or last observed
    private int lastQueryType = -1;

    // C. Response-Level
    private long totalAnswerCount = 0; // redundant with totalAnCount? Check definition.
    // "dns_answer_count: Total number of answers returned." -> Refers to Response
    // packets logic.

    private Set<Integer> answerRrTypes = new HashSet<>();
    private long sumTtl = 0;
    private long maxTtl = Long.MIN_VALUE;
    private long minTtl = Long.MAX_VALUE;
    private long ttlCount = 0;

    // D. Flow-Level
    private Set<String> uniqueDomains = new HashSet<>();
    private Map<Integer, Integer> rrTypeCounts = new HashMap<>(); // For entropy

    // E. Rate / Temporal
    private long nxDomainCount = 0;

    // F. Size & EDNS
    private boolean hasEdns = false;
    private int ednsUdpSize = 0;
    private long totalResponseSize = 0;

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

        // A. Header Parsing
        boolean isResponse = header.isResponse();
        if (isResponse) {
            dnsQrResponseCount++;
        } else {
            dnsQrQueryCount++;
        }

        lastOpCode = (int) header.getOpCode().value();
        lastRCode = (int) header.getrCode().value();

        totalQdCount += header.getQdCountAsInt();
        totalAnCount += header.getAnCountAsInt();
        totalNsCount += header.getNsCountAsInt();
        totalArCount += header.getArCountAsInt();

        // Check for NXDOMAIN
        if (isResponse && header.getrCode() == DnsRCode.NX_DOMAIN) {
            nxDomainCount++;
        }

        // Response Size tracking
        if (isResponse) {
            totalResponseSize += length;
        }

        // Check for EDNS in Additional Records
        for (DnsResourceRecord rr : header.getAdditionalInfo()) {
            if (rr.getDataType() == DnsResourceRecordType.OPT) {
                hasEdns = true;
                // OPT RR class field contains UDP payload size
                ednsUdpSize = rr.getDataClass().value() & 0xFFFF;
            }
        }

        // B. Query Parsing (Questions)
        for (DnsQuestion q : header.getQuestions()) {
            String qName = q.getQName().getName();
            uniqueDomains.add(qName);
            totalQueryLength += qName.length(); // bytes estimate
            lastQueryType = (int) q.getQType().value();
            queryCount++;

            recordRrType((int) q.getQType().value());
        }

        // C. Response Parsing (Answers)
        if (isResponse) {
            for (DnsResourceRecord rr : header.getAnswers()) {
                answerRrTypes.add((int) rr.getDataType().value());
                long ttl = rr.getTtl() & 0xFFFFFFFFL; // unsigned int

                sumTtl += ttl;
                if (ttl > maxTtl)
                    maxTtl = ttl;
                if (ttl < minTtl)
                    minTtl = ttl;
                ttlCount++;

                recordRrType((int) rr.getDataType().value());
            }
        }
    }

    private void recordRrType(int type) {
        rrTypeCounts.put(type, rrTypeCounts.getOrDefault(type, 0) + 1);
    }

    // Getters for Features

    public boolean isDnsFlow() {
        return isDns;
    }

    // Header
    public int getDnsQr() {
        // 0 if only queries, 1 if only responses, 2 if both (mixed/flow),
        // BUT requirement says "Query/Response flag status".
        // For a flow, it might be ambiguous. Let's return 1 if we saw ANY response
        // (completed interaction).
        return (dnsQrResponseCount > 0) ? 1 : 0;
    }

    public int getDnsOpCode() {
        return lastOpCode == -1 ? 0 : lastOpCode;
    }

    public int getDnsRCode() {
        return lastRCode == -1 ? 0 : lastRCode;
    }

    public long getDnsQdCount() {
        return totalQdCount;
    }

    public long getDnsAnCount() {
        return totalAnCount;
    }

    public long getDnsNsCount() {
        return totalNsCount;
    }

    public long getDnsArCount() {
        return totalArCount;
    }

    // Query
    public double getDnsQueryLengthMean() {
        return queryCount == 0 ? 0 : (double) totalQueryLength / queryCount;
    }

    public int getDnsQueryType() {
        return lastQueryType == -1 ? 0 : lastQueryType;
    }

    // Response
    public long getDnsAnswerCount() {
        return ttlCount;
    } // Logic: count of answers processed

    public int getDnsAnswerRrTypesCount() {
        return answerRrTypes.size();
    }

    public double getDnsAnswerTtlsMean() {
        return ttlCount == 0 ? 0 : (double) sumTtl / ttlCount;
    }

    public long getDnsAnswerTtlsMax() {
        return maxTtl == Long.MIN_VALUE ? 0 : maxTtl;
    }

    public long getDnsAnswerTtlsMin() {
        return minTtl == Long.MAX_VALUE ? 0 : minTtl;
    }

    // Flow
    public int getDnsUniqueDomains() {
        return uniqueDomains.size();
    }

    public double getDnsRrTypeEntropy() {
        if (rrTypeCounts.isEmpty())
            return 0.0;
        double entropy = 0.0;
        long total = 0;
        for (int count : rrTypeCounts.values())
            total += count;

        for (int count : rrTypeCounts.values()) {
            double p = (double) count / total;
            entropy -= p * Math.log(p) / Math.log(2);
        }
        return entropy;
    }

    // Rate
    public double getQueriesPerSecond(double durationSec) {
        if (durationSec <= 0)
            return 0.0;
        return dnsQrQueryCount / durationSec;
    }

    public double getNxDomainRate() {
        if (dnsQrResponseCount == 0)
            return 0.0;
        return (double) nxDomainCount / dnsQrResponseCount;
    }

    // EDNS / Size
    public int getDnsEdnsPresent() {
        return hasEdns ? 1 : 0;
    }

    public int getDnsEdnsUdpSize() {
        return ednsUdpSize;
    }

    public long getDnsResponseSize() {
        return totalResponseSize;
    }

    // Helpers
    public long getDnsTotalQueries() {
        return dnsQrQueryCount;
    }

    public long getDnsTotalResponses() {
        return dnsQrResponseCount;
    }
}
