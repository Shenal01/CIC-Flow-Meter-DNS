package com.antigravity.traffic;

import org.apache.commons.cli.*;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.sql.Timestamp;

public class CicFlowMeter {

    public static void main(String[] args) {
        Options options = new Options();
        options.addOption("f", "file", true, "Input PCAP file");
        options.addOption("i", "interface", true, "Network Interface");
        options.addOption("o", "output", true, "Output CSV file");

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);

            String pcapFile = cmd.getOptionValue("f");
            String ifaceName = cmd.getOptionValue("i");
            String outputFile = cmd.getOptionValue("o", "flow_output.csv");

            if (pcapFile == null && ifaceName == null) {
                System.out.println("Please specify input file (-f) or interface (-i)");
                return;
            }

            try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
                FlowManager flowManager = new FlowManager(writer);
                PcapHandle handle;

                if (pcapFile != null) {
                    System.out.println("Reading from file: " + pcapFile);
                    handle = Pcaps.openOffline(pcapFile);
                } else {
                    PcapNetworkInterface nif = Pcaps.getDevByName(ifaceName);
                    if (nif == null) {
                        System.out.println("Interface not found: " + ifaceName);
                        return;
                    }
                    System.out.println("Listening on interface: " + ifaceName);
                    int snapLen = 65536;
                    PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
                    int timeout = 10;
                    handle = nif.openLive(snapLen, mode, timeout);
                }

                PcapHandle finalHandle = handle;
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("\nStopping capture and dumping flows...");
                    try {
                        if (finalHandle != null && finalHandle.isOpen()) {
                            finalHandle.breakLoop();
                        }
                        flowManager.dumpAll();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }));

                // Keep looping
                try {
                    handle.loop(-1, new PacketListener() {
                        @Override
                        public void gotPacket(Packet packet) {
                            Timestamp ts = finalHandle.getTimestamp();
                            flowManager.processPacket(packet, ts);
                        }
                    });
                } catch (InterruptedException e) {
                    System.out.println("Interrupted");
                } catch (PcapNativeException | NotOpenException e) {
                    // End of file usually throws NotOpenException or just stops
                    System.out.println("Capture ended or error: " + e.getMessage());
                }

                flowManager.dumpAll();
                handle.close();
                System.out.println("Done. Output written to " + outputFile);

            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (ParseException e) {
            System.out.println("Command parsing failed: " + e.getMessage());
        }
    }
}
