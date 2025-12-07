package com.antigravity.traffic;

import org.pcap4j.packet.Packet;

public class Flow {
    private final FlowKey key;
    private final long startTime;
    private long lastPacketTime;

    // Direction stats
    private BasicStats fwdPayloadStats = new BasicStats();
    private BasicStats bwdPayloadStats = new BasicStats();
    private BasicStats fwdIatStats = new BasicStats();
    private BasicStats bwdIatStats = new BasicStats();
    private BasicStats flowIatStats = new BasicStats();
    private BasicStats flowLengthStats = new BasicStats(); // Total length (headers included or excluded? typically
                                                           // payload or wire len. using wire len for simplicity)

    // Packet timestamps for IAT
    private long lastFwdTime = 0;
    private long lastBwdTime = 0;

    private long fwdCount = 0;
    private long bwdCount = 0;

    // DNS Feature Extractor
    private DnsFeatureExtractor dnsExtractor;

    public Flow(FlowKey key, long startTime, boolean isDnsPort) {
        this.key = key;
        this.startTime = startTime;
        this.lastPacketTime = startTime;

        // Initialize DNS extractor if relevant (Port 53)
        // Note: Logic could be in FlowManager to decide when to create this
        if (isDnsPort) {
            this.dnsExtractor = new DnsFeatureExtractor();
        }
    }

    public void addPacket(Packet packet, long timestamp, boolean isForward) {
        long currentLast = lastPacketTime;

        // Flow Inter-Arrival Time
        if (fwdCount + bwdCount > 0) {
            flowIatStats.addValue(timestamp - currentLast);
        }

        int length = packet.length();
        flowLengthStats.addValue(length);

        if (isForward) {
            if (fwdCount > 0) {
                fwdIatStats.addValue(timestamp - lastFwdTime);
            }
            lastFwdTime = timestamp;
            fwdPayloadStats.addValue(length); // Using full length for simplicity, CIC flow meter logic varies
            fwdCount++;
        } else {
            if (bwdCount > 0) {
                bwdIatStats.addValue(timestamp - lastBwdTime);
            }
            lastBwdTime = timestamp;
            bwdPayloadStats.addValue(length);
            bwdCount++;
        }

        lastPacketTime = timestamp;

        // DNS Inspection
        if (dnsExtractor != null) {
            dnsExtractor.processPacket(packet, length);
        }
    }

    public FlowKey getKey() {
        return key;
    }

    public long getLastPacketTime() {
        return lastPacketTime;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getFlowDuration() {
        return lastPacketTime - startTime;
    }

    // Logic to export as CSV row
    public String toCsvRow() {
        StringBuilder sb = new StringBuilder();

        // 5-tuple
        sb.append(key.getSrcIp().getHostAddress()).append(",");
        sb.append(key.getDstIp().getHostAddress()).append(",");
        sb.append(key.getSrcPort()).append(",");
        sb.append(key.getDstPort()).append(",");
        sb.append(key.getProtocol()).append(",");

        // Basic Stats
        sb.append(getFlowDuration()).append(",");
        sb.append(fwdCount).append(",");
        sb.append(bwdCount).append(",");

        sb.append(flowLengthStats.getMean()).append(",");
        sb.append(flowLengthStats.getStdDev()).append(",");
        sb.append(flowLengthStats.getMax()).append(",");

        sb.append(flowIatStats.getMean()).append(",");
        sb.append(flowIatStats.getStdDev()).append(",");
        sb.append(flowIatStats.getMax()).append(",");

        // DNS Features
        if (dnsExtractor != null && dnsExtractor.isDnsFlow()) {
            double durationSec = getFlowDuration() / 1000.0; // Duration is usually in ms? Assuming ms based on typical
                                                             // System.currentTimeMillis
            // Check FlowManager/Main timestamps. usually microseconds or nanoseconds in
            // libpcap, but here startTime logic depends on caller.
            // Assuming milliseconds for safety or check caller.

            // 1. Header
            sb.append(dnsExtractor.getDnsQr()).append(",");
            sb.append(dnsExtractor.getDnsOpCode()).append(",");
            sb.append(dnsExtractor.getDnsRCode()).append(",");
            sb.append(dnsExtractor.getDnsQdCount()).append(",");
            sb.append(dnsExtractor.getDnsAnCount()).append(",");
            sb.append(dnsExtractor.getDnsNsCount()).append(",");
            sb.append(dnsExtractor.getDnsArCount()).append(",");

            // 2. Query
            sb.append(dnsExtractor.getDnsQueryLengthMean()).append(",");
            sb.append(dnsExtractor.getDnsQueryType()).append(",");

            // 3. Response
            sb.append(dnsExtractor.getDnsAnswerCount()).append(",");
            sb.append(dnsExtractor.getDnsAnswerRrTypesCount()).append(",");
            sb.append(dnsExtractor.getDnsAnswerTtlsMean()).append(",");
            sb.append(dnsExtractor.getDnsAnswerTtlsMax()).append(",");
            sb.append(dnsExtractor.getDnsAnswerTtlsMin()).append(",");

            // 4. Flow
            sb.append(dnsExtractor.getDnsTotalQueries()).append(",");
            sb.append(dnsExtractor.getDnsTotalResponses()).append(",");
            sb.append(dnsExtractor.getDnsUniqueDomains()).append(",");
            sb.append(dnsExtractor.getDnsRrTypeEntropy()).append(",");

            // 5. Rate
            sb.append(dnsExtractor.getQueriesPerSecond(durationSec)).append(",");
            sb.append(dnsExtractor.getNxDomainRate()).append(",");

            // 6. EDNS / Size
            sb.append(dnsExtractor.getDnsEdnsPresent()).append(",");
            sb.append(dnsExtractor.getDnsEdnsUdpSize()).append(",");
            sb.append(dnsExtractor.getDnsResponseSize());

        } else {
            // Fill with 0s for non-DNS or non-DNS flows.
            // Count: 7 (Header) + 2 (Query) + 5 (Response) + 4 (Flow) + 3 (Rate) + 3 (EDNS)
            // = 24 cols
            sb.append("0,0,0,0,0,0,0,"); // Header
            sb.append("0,0,"); // Query
            sb.append("0,0,0,0,0,"); // Response
            sb.append("0,0,0,0,"); // Flow
            sb.append("0,0,"); // Rate
            sb.append("0,0,0"); // EDNS
        }

        return sb.toString();
    }

    public static String getCsvHeader() {
        return "Src IP,Dst IP,Src Port,Dst Port,Protocol," +
                "Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts," +
                "Flow Len Mean,Flow Len Std,Flow Len Max," +
                "Flow IAT Mean,Flow IAT Std,Flow IAT Max," +
                // 1. Header
                "dns_qr,dns_opcode,dns_rcode,dns_qdcount,dns_ancount,dns_nscount,dns_arcount," +
                // 2. Query
                "dns_query_length,dns_query_type," +
                // 3. Response
                "dns_answer_count,dns_answer_rrtypes,dns_answer_ttls_mean,dns_answer_ttls_max,dns_answer_ttls_min," +
                // 4. Flow
                "dns_total_queries,dns_total_responses,dns_unique_domains,dns_rrtype_entropy," +
                // 5. Rate
                "queries_per_second,nxdomain_rate," +
                // 6. EDNS
                "dns_edns_present,dns_edns_udp_size,dns_response_size";
    }
}
