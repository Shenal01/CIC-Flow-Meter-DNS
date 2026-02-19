import subprocess
import os

tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
pcap_path = r"C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\DNS_Spoofing.pcap"

flows = [
    {
        "name": "flow1",
        "filter": "ip.addr==192.168.137.102 && ip.addr==13.225.196.108 && tcp.port==35028 && tcp.port==443",
        "fields": ["frame.time_epoch", "ip.src", "frame.len", "tcp.len"]
    },
    {
        "name": "flow2",
        "filter": "ip.addr==192.168.137.49 && ip.addr==205.174.165.69 && udp.port==34062 && udp.port==64343",
        "fields": ["frame.time_epoch", "ip.src", "frame.len", "udp.length"]
    },
    {
        "name": "flow3",
        "filter": "ip.addr==192.168.137.72 && ip.addr==255.255.255.255 && udp.port==49154 && udp.port==6667",
        "fields": ["frame.time_epoch", "ip.src", "frame.len", "udp.length"]
    }
]

for flow in flows:
    output_file = f"{flow['name']}.txt"
    print(f"Extracting to {output_file}...")
    
    cmd = [tshark_path, "-r", pcap_path, "-Y", flow['filter'], "-T", "fields"]
    for field in flow['fields']:
        cmd.extend(["-e", field])
        
    with open(output_file, "w") as f:
        subprocess.run(cmd, stdout=f, check=True)
    
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        print(f"Success: {output_file}")
    else:
        print(f"Failed: {output_file} is empty")
