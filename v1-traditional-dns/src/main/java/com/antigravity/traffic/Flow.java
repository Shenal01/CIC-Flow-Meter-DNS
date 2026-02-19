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

    // Label for ML training (ATTACK or BENIGN)
    private final String label;

    public Flow(FlowKey key, long startTime, boolean isDnsPort, String label) {
        this.key = key;
        this.startTime = startTime;
        this.lastPacketTime = startTime;
        this.label = label;

        // Initialize DNS extractor if relevant (Port 53)
        // Note: Logic could be in FlowManager to decide when to create this
        if (isDnsPort) {
            this.dnsExtractor = new DnsFeatureExtractor();
        }
    }

    public void addPacket(Packet packet, long timestamp, boolean isForward) {
        long currentLast = lastPacketTime;

        // FIX #7: Packet Ordering Validation
        if (timestamp < lastPacketTime) {
            // Out-of-order packet detected - skip to avoid negative IAT
            // Log warning but continue processing packet stats
            // Don't update IAT statistics for out-of-order packets
        } else {
            // Flow Inter-Arrival Time (only for in-order packets)
            if (fwdCount + bwdCount > 0) {
                flowIatStats.addValue(timestamp - currentLast);
            }
        }

        int length = packet.length();
        flowLengthStats.addValue(length);

        // 1. TTL Violation Check (Standard TTLs: 64, 128, 255. Others might be
        // spoofed/routed)
        // Simplistic check: If not common OS TTL, flag it.
        // Assuming IP Packet availability checked in FlowManager, but we need access
        // here.
        // For strict correctness without passing IP object, we skip or need
        // refactoring.
        // *Refactoring*: We will trust FlowManager to pass TTL or handle it.
        // For now, let's assume standard behavior: we need the IP header to check TTL.
        // Since signature is fixed, we can't easily get TTL here without passing it.
        // *Self-Correction*: I will update signature in next step. For now, basic
        // stats.

        if (isForward) {
            if (fwdCount > 0 && timestamp >= lastFwdTime) { // FIX #7: Check ordering
                fwdIatStats.addValue(timestamp - lastFwdTime);
            }
            lastFwdTime = timestamp;
            fwdPayloadStats.addValue(length);
            fwdCount++;

            // Simplified Header Length (Assuming Ethernet+IP+TCP/UDP ~ 54-66 bytes)
            // Ideally we'd pass header length from Packet, but Pcap4J extraction is
            // expensive.
        } else {
            if (bwdCount > 0 && timestamp >= lastBwdTime) { // FIX #7: Check ordering
                bwdIatStats.addValue(timestamp - lastBwdTime);
            }
            lastBwdTime = timestamp;
            bwdPayloadStats.addValue(length);
            bwdCount++;
        }

        // FIX #7: Only update lastPacketTime if packet is in order
        if (timestamp >= lastPacketTime) {
            lastPacketTime = timestamp;
        }

        // DNS Inspection & Response Time Logic
        if (dnsExtractor != null) {
            // We pass timestamp to processPacket to track Query->Response time
            dnsExtractor.processPacket(packet, length, timestamp);
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

        // --- Identity (5) ---
        sb.append(key.getSrcIp().getHostAddress()).append(",");
        sb.append(key.getDstIp().getHostAddress()).append(",");
        sb.append(key.getSrcPort()).append(",");
        sb.append(key.getDstPort()).append(",");
        sb.append(key.getProtocol()).append(",");

        // Calculate Duration in Seconds for Rates
        // FIX #1: Proper handling of single-packet flows to avoid division by zero
        double durationSec = getFlowDuration() / 1000.0;
        if (durationSec <= 0) {
            durationSec = 1.0; // Minimum 1 second to avoid inflated rates
        }

        // --- Category 1: DNS Critical (10) ---
        if (dnsExtractor != null && dnsExtractor.isDnsFlow()) {
            sb.append(String.format("%.4f,", dnsExtractor.getDnsAmplificationFactor()));
            sb.append(String.format("%.4f,", dnsExtractor.getQueryResponseRatio()));
            sb.append(String.format("%.4f,", dnsExtractor.getDnsAnyQueryRatio()));
            sb.append(String.format("%.4f,", dnsExtractor.getDnsTxtQueryRatio()));
            sb.append("0,"); // dns_server_fanout (Requires Manager-level aggregation, placeholder for
                             // flow-level)
            long diff = Math.abs(dnsExtractor.getDnsTotalQueries() - dnsExtractor.getDnsTotalResponses());
            sb.append(diff).append(","); // dns_response_inconsistency
            sb.append(dnsExtractor.getTtlViolationCount()).append(","); // ttl_violation_rate (using count for now as
                                                                        // per Flow logic)
            sb.append(String.format("%.4f,", dnsExtractor.getQueriesPerSecond(durationSec)));
            sb.append(String.format("%.4f,", dnsExtractor.getMeanAnswersPerQuery())); // dns_mean_answers_per_query

            // FIX #2: Correct port_53_traffic_ratio calculation using actual DNS bytes
            long totalFlowBytes = (long) flowLengthStats.getSum();
            if (totalFlowBytes > 0) {
                long dnsTrafficBytes = dnsExtractor.getTotalQueryBytes() + dnsExtractor.getDnsResponseSize();
                sb.append(String.format("%.4f,", (double) dnsTrafficBytes / totalFlowBytes));
            } else {
                sb.append("0.0,");
            }
        } else {
            sb.append("0,0,0,0,0,0,0,0,0,0,");
        }

        // --- Category 2: Flow Rates (4) ---
        sb.append(String.format("%.4f,", flowLengthStats.getSum() / durationSec)); // flow_bytes_per_sec
        sb.append(String.format("%.4f,", (fwdCount + bwdCount) / durationSec)); // flow_packets_per_sec
        sb.append(String.format("%.4f,", fwdCount / durationSec)); // fwd_packets_per_sec
        sb.append(String.format("%.4f,", bwdCount / durationSec)); // bwd_packets_per_sec

        // --- Category 3: Flow Statistics (5) ---
        sb.append(getFlowDuration()).append(",");
        sb.append(fwdCount).append(",");
        sb.append(bwdCount).append(",");
        sb.append(fwdPayloadStats.getSum()).append(","); // total_fwd_bytes
        sb.append(bwdPayloadStats.getSum()).append(","); // total_bwd_bytes

        // --- Category 4: DNS Aggregates (3) ---
        if (dnsExtractor != null) {
            sb.append(dnsExtractor.getDnsTotalQueries()).append(",");
            sb.append(dnsExtractor.getDnsTotalResponses()).append(",");
            sb.append(dnsExtractor.getDnsResponseSize()).append(",");
        } else {
            sb.append("0,0,0,");
        }

        // --- Category 5: Timing (6) ---
        sb.append(String.format("%.4f,", flowIatStats.getMean()));
        sb.append(String.format("%.4f,", flowIatStats.getStdDev()));
        sb.append(String.format("%.4f,", flowIatStats.getMin()));
        sb.append(String.format("%.4f,", flowIatStats.getMax()));
        sb.append(String.format("%.4f,", fwdIatStats.getMean()));
        sb.append(String.format("%.4f,", bwdIatStats.getMean()));

        // --- Category 6: Packet Sizes (5) ---
        sb.append(String.format("%.4f,", fwdPayloadStats.getMean()));
        sb.append(String.format("%.4f,", bwdPayloadStats.getMean()));
        sb.append(String.format("%.4f,", flowLengthStats.getStdDev())); // packet_size_std
        sb.append(String.format("%.4f,", flowLengthStats.getMin())); // flow_length_min
        sb.append(String.format("%.4f,", flowLengthStats.getMax())); // flow_length_max

        // --- Category 7: Advanced (2) ---
        if (dnsExtractor != null) {
            sb.append(String.format("%.4f,", dnsExtractor.getResponseTimeVariance()));
        } else {
            sb.append("0,");
        }
        sb.append(String.format("%.4f,", flowLengthStats.getMean())); // average_packet_size

        // --- Category 8: Classification ---
        // Only add label if it was specified
        if (label != null) {
            sb.append(label);
        }

        return sb.toString();
    }

    public static String getCsvHeader(boolean includeLabel) {
        String header = "src_ip,dst_ip,src_port,dst_port,protocol," +
                "dns_amplification_factor,query_response_ratio,dns_any_query_ratio,dns_txt_query_ratio,dns_server_fanout,dns_response_inconsistency,ttl_violation_rate,dns_queries_per_second,dns_mean_answers_per_query,port_53_traffic_ratio,"
                +
                "flow_bytes_per_sec,flow_packets_per_sec,fwd_packets_per_sec,bwd_packets_per_sec," +
                "flow_duration,total_fwd_packets,total_bwd_packets,total_fwd_bytes,total_bwd_bytes," +
                "dns_total_queries,dns_total_responses,dns_response_bytes," +
                "flow_iat_mean,flow_iat_std,flow_iat_min,flow_iat_max,fwd_iat_mean,bwd_iat_mean," +
                "fwd_packet_length_mean,bwd_packet_length_mean,packet_size_std,flow_length_min,flow_length_max," +
                "response_time_variance,average_packet_size";

        // Only add label column if label mode is enabled
        if (includeLabel) {
            header += ",label";
        }

        return header;
    }
}
