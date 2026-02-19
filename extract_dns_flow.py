import subprocess
import pandas as pd

tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
pcap_path = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\CIC_IOT_2023\Attacks\DNS_Spoofing.pcap"
csv_path = r"C:\Users\shenal\Downloads\reseraach\PCAPS_Used\CIC_IOT_2023\Attacks\DNS_Spoofing.csv"

def find_first_dns_flow():
    print("Searching for first DNS/Port 53 packet...")
    # Find the first packet with udp.port == 53
    cmd = [
        tshark_path, "-r", pcap_path,
        "-Y", "udp.port==53", 
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", 
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-c", "1" 
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        
        if not output:
            print("[FAIL] No Port 53 traffic found in the entire PCAP.")
            return
            
        print(f"[PASS] Found DNS Packet: {output}")
        parts = output.split('\t')
        if len(parts) < 4:
            return

        src_ip = parts[0]
        dst_ip = parts[1]
        src_port = int(parts[2])
        dst_port = int(parts[3])
        
        print("\nSearching CSV for this flow...")
        df = pd.read_csv(csv_path)
        
        # Filter for this specific interaction
        # Note: CSV might have aggregated multiple packets, but keys should match
        match = df[
            (df['src_ip'] == src_ip) & 
            (df['dst_ip'] == dst_ip) & 
            (df['src_port'] == src_port) & 
            (df['dst_port'] == dst_port)
        ]
        
        if match.empty:
            # Try reverse direction
            match = df[
                (df['src_ip'] == dst_ip) & 
                (df['dst_ip'] == src_ip) & 
                (df['src_port'] == dst_port) & 
                (df['dst_port'] == src_port)
            ]
            
        if not match.empty:
            row = match.iloc[0]
            print("\n--- CSV ROW FOUND ---")
            print(f"Protocol: {row.get('protocol', 'N/A')}")
            print(f"DNS Ratio: {row.get('query_response_ratio', 'N/A')}")
            print(f"Port 53 Ratio: {row.get('port_53_traffic_ratio', 'N/A')}")
        else:
            print("❌ Flow not found in CSV (Might be filtered or timed out differently)")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    find_first_dns_flow()
