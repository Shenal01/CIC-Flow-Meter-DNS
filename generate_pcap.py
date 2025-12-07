import struct
import time

def create_pcap(filename):
    # Global Header
    pcap_global_header = struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    timestamp = int(time.time())
    packets = []

    # 1. Standard Query (A record for example.com)
    # --------------------------------------------
    eth = b'\x00\x00\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x01' + b'\x08\x00'
    ip_base = b'\x45\x00\x00\x00\x00\x00\x40\x11\x00\x00\x01\x02\x03\x04\x08\x08\x08\x08' # Checksum 0
    # Query: example.com, Type A, Class IN
    dns_payload_q = b'\x11\x11\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
                    b'\x07example\x03com\x00' + \
                    b'\x00\x01\x00\x01'
    udp_len_q = 8 + len(dns_payload_q)
    # Update IP len
    ip_header_q = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + udp_len_q, 0, 0, 64, 17, 0, b'\x01\x02\x03\x04', b'\x08\x08\x08\x08')
    udp_header_q = struct.pack('!HHHH', 12345, 53, udp_len_q, 0)
    packets.append(eth + ip_header_q + udp_header_q + dns_payload_q)

    # 2. Response (NXDOMAIN)
    # ----------------------
    # ID matches, QR=1, OpCode=0, RCode=3 (NXDOMAIN) -> Flags: 0x8183 
    # (QR=1, Op=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=3)
    dns_payload_r = b'\x11\x11\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00' + \
                    b'\x07example\x03com\x00' + \
                    b'\x00\x01\x00\x01'
    udp_len_r = 8 + len(dns_payload_r)
    ip_header_r = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + udp_len_r, 0, 0, 64, 17, 0, b'\x08\x08\x08\x08', b'\x01\x02\x03\x04')
    udp_header_r = struct.pack('!HHHH', 53, 12345, udp_len_r, 0)
    packets.append(eth + ip_header_r + udp_header_r + dns_payload_r)

    # 3. Query with EDNS (OPT Record)
    # -------------------------------
    # Query: test.com, Type A
    # + Additional Record: Type 41 (OPT), Class 4096 (UDP Payload size)
    dns_payload_e = b'\x22\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01' + \
                    b'\x04test\x03com\x00' + \
                    b'\x00\x01\x00\x01' + \
                    b'\x00' + \
                    b'\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00' # Root, Type 41, Class 4096, TTL 0, Len 0
    udp_len_e = 8 + len(dns_payload_e)
    ip_header_e = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + udp_len_e, 0, 0, 64, 17, 0, b'\x01\x02\x03\x04', b'\x08\x08\x08\x08')
    udp_header_e = struct.pack('!HHHH', 12345, 53, udp_len_e, 0)
    packets.append(eth + ip_header_e + udp_header_e + dns_payload_e)

    # Write PCAP
    with open(filename, 'wb') as f:
        f.write(pcap_global_header)
        for pkt in packets:
            pcap_packet_header = struct.pack('IIII', int(time.time()), 0, len(pkt), len(pkt))
            f.write(pcap_packet_header)
            f.write(pkt)
        
    print(f"Created {filename} with 3 packets (Standard Query, NXDOMAIN Response, EDNS Query)")

if __name__ == "__main__":
    create_pcap("verification_traffic.pcap")
