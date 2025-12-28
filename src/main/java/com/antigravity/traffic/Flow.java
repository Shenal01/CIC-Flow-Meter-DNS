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

        // DNS Features (Infrastructure Focused)
        if (dnsExtractor != null && dnsExtractor.isDnsFlow()) {
            double durationSec = getFlowDuration() / 1000.0;

            // 1. Direct / Header
            sb.append(dnsExtractor.getDnsQr()).append(",");
            sb.append(dnsExtractor.getDnsOpCode()).append(",");
            sb.append(dnsExtractor.getDnsQdCount()).append(",");
            sb.append(dnsExtractor.getDnsQueryType()).append(",");
            sb.append(dnsExtractor.getDnsAnswerCount()).append(",");

            // 2. Derived Counts & Rates
            sb.append(dnsExtractor.getDnsTotalQueries()).append(",");
            sb.append(dnsExtractor.getDnsTotalResponses()).append(",");
            sb.append(dnsExtractor.getQueriesPerSecond(durationSec)).append(",");

            // 3. EDNS & Size
            sb.append(dnsExtractor.getDnsEdnsPresent()).append(",");
            sb.append(dnsExtractor.getDnsEdnsUdpSize()).append(",");
            sb.append(dnsExtractor.getDnsResponseSize()).append(",");

            // 4. New Infrastructure Ratios
            sb.append(dnsExtractor.getDnsAmplificationFactor()).append(",");
            sb.append(dnsExtractor.getQueryResponseRatio()).append(",");
            sb.append(dnsExtractor.getPacketSizeStdDev()).append(",");
            sb.append(dnsExtractor.getDnsAnyQueryRatio()).append(",");
            sb.append(dnsExtractor.getDnsTxtQueryRatio());

        } else {
            // Fill with 0s for non-DNS flows.
            // Total 16 features
            sb.append("0,0,0,0,0,"); // Direct (5)
            sb.append("0,0,0,"); // Rate (3)
            sb.append("0,0,0,"); // EDNS (3)
            sb.append("0,0,0,0,0"); // New Ratios (5)
        }

        return sb.toString();
    }

    public static String getCsvHeader() {
        return "Src IP,Dst IP,Src Port,Dst Port,Protocol," +
                "Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts," +
                "Flow Len Mean,Flow Len Std,Flow Len Max," +
                "Flow IAT Mean,Flow IAT Std,Flow IAT Max," +
                // 1. Direct
                "dns_qr,dns_opcode,dns_qdcount,dns_query_type,dns_answer_count," +
                // 2. Counts & Rates
                "dns_total_queries,dns_total_responses,queries_per_second," +
                // 3. EDNS & Size
                "dns_edns_present,dns_edns_udp_size,dns_response_size," +
                // 4. New Infrastructure Ratios
                "dns_amplification_factor,query_response_ratio,packet_size_stddev,dns_any_query_ratio,dns_txt_query_ratio";
    }
}
