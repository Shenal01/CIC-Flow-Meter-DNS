import subprocess

tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
pcap_path = r"C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\DNS_Spoofing.pcap"

cmd = [
    tshark_path, 
    "-r", pcap_path, 
    "-Y", "ip.src==192.168.137.163 && ip.dst==192.168.137.1 && udp.srcport==47935 && udp.dstport==53", 
    "-T", "fields", 
    "-e", "frame.time_epoch", 
    "-e", "dns.flags.response", 
    "-e", "frame.len"
]

print("Running Tshark to verify DNS flags...")
try:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    output = result.stdout.strip()
    
    if not output:
        print("No packets found matching filter.")
    else:
        print("\n--- Tshark Output ---")
        print(output)
        print("\n--- Verification ---")
        for line in output.splitlines():
            parts = line.split('\t')
            if len(parts) >= 2:
                flags = parts[1]
                type_str = "Response" if flags == "1" else "Query"
                print(f"Packet: Flag={flags} ({type_str}) -> VALID DNS")

except subprocess.CalledProcessError as e:
    print(f"Error running tshark: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
