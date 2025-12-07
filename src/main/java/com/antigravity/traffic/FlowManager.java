package com.antigravity.traffic;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintWriter;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FlowManager {
    private static final Logger logger = LoggerFactory.getLogger(FlowManager.class);

    private final Map<FlowKey, Flow> activeFlows = new HashMap<>();
    private final PrintWriter csvWriter;
    private final long flowTimeoutMillis = 120000; // 2 minutes timeout

    public FlowManager(PrintWriter csvWriter) {
        this.csvWriter = csvWriter;
        // Write Header
        csvWriter.println(Flow.getCsvHeader());
        csvWriter.flush();
    }

    public void processPacket(Packet packet, Timestamp timestamp) {
        if (packet == null)
            return;

        IpV4Packet ipPacket = packet.get(IpV4Packet.class);
        if (ipPacket == null)
            return; // Only IPv4 for this demo

        InetAddress srcIp = ipPacket.getHeader().getSrcAddr();
        InetAddress dstIp = ipPacket.getHeader().getDstAddr();
        int srcPort = 0;
        int dstPort = 0;
        String protocol = "";

        boolean isTcp = false;
        boolean isUdp = false;

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            dstPort = tcp.getHeader().getDstPort().valueAsInt();
            protocol = "TCP";
            isTcp = true;
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            srcPort = udp.getHeader().getSrcPort().valueAsInt();
            dstPort = udp.getHeader().getDstPort().valueAsInt();
            protocol = "UDP";
            isUdp = true;
        } else {
            return; // Ignore non-TCP/UDP
        }

        // Define Flow Keys
        FlowKey fwdKey = new FlowKey(srcIp, dstIp, srcPort, dstPort, protocol);
        FlowKey bwdKey = new FlowKey(dstIp, srcIp, dstPort, srcPort, protocol);

        Flow flow;
        boolean isForward;

        if (activeFlows.containsKey(fwdKey)) {
            flow = activeFlows.get(fwdKey);
            isForward = true;
        } else if (activeFlows.containsKey(bwdKey)) {
            flow = activeFlows.get(bwdKey);
            isForward = false;
        } else {
            // New Flow
            boolean isDns = (srcPort == 53 || dstPort == 53);
            flow = new Flow(fwdKey, timestamp.getTime(), isDns);
            activeFlows.put(fwdKey, flow);
            isForward = true;
        }

        // Update Flow
        flow.addPacket(packet, timestamp.getTime(), isForward);

        // Check TCP FIN/RST for termination (Optional optimization)
        if (isTcp) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            if (tcp.getHeader().getFin() || tcp.getHeader().getRst()) {
                // Terminate flow? Usually we wait for timeout or full handshake close,
                // but for simplicity we can just keep until timeout or aggressive close.
            }
        }

        checkTimeout(timestamp.getTime());
    }

    private void checkTimeout(long currentTime) {
        List<FlowKey> toRemove = new ArrayList<>();

        for (Map.Entry<FlowKey, Flow> entry : activeFlows.entrySet()) {
            Flow flow = entry.getValue();
            if ((currentTime - flow.getLastPacketTime()) > flowTimeoutMillis) {
                exportFlow(flow);
                toRemove.add(entry.getKey());
            }
        }

        for (FlowKey key : toRemove) {
            activeFlows.remove(key);
        }
    }

    public void dumpAll() {
        for (Flow flow : activeFlows.values()) {
            exportFlow(flow);
        }
        activeFlows.clear();
        csvWriter.flush();
    }

    private void exportFlow(Flow flow) {
        csvWriter.println(flow.toCsvRow());
    }
}
