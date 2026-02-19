import statistics
import math
import sys

# CSV Baseline Values (from Step 576)
csv_rows = {
    "flow1": {
        "flow_duration": 415,
        "total_fwd_packets": 11,
        "total_bwd_packets": 13,
        "total_fwd_bytes": 2383.0,
        "total_bwd_bytes": 8945.0,
        "flow_bytes_per_sec": 27296.3855,
        "flow_packets_per_sec": 57.8313,
        "fwd_packet_length_mean": 216.6364,
        "bwd_packet_length_mean": 688.0769,
        "large_packet_ratio": 0.3333,
        "medium_packet_ratio": 0.0833,
        "small_packet_ratio": 0.5833,
        "protocol": "TCP" # implied
    },
    "flow2": {
        "flow_duration": 30142,
        "total_fwd_packets": 4,
        "total_bwd_packets": 0,
        "total_fwd_bytes": 376.0,
        "total_bwd_bytes": 0.0,
        "fwd_packet_length_mean": 94.0,
        "large_packet_ratio": 0.0,
        "small_packet_ratio": 1.0
    },
    "flow3": {
        "flow_duration": 295004,
        "total_fwd_packets": 60,
        "total_bwd_packets": 0,
        "total_fwd_bytes": 13800.0,
        "total_bwd_bytes": 0.0,
        "fwd_packet_length_mean": 230.0,
        "large_packet_ratio": 0.0,
        "small_packet_ratio": 1.0,
        "protocol": "UDP"
    }
}

def analyze_flow(name):
    filename = f"{name}.txt"
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return

    print(f"\n--- Analysis for {name} ---")
    
    timestamps = []
    src_ips = []
    frame_lens = []
    
    # Parsing Tshark Output
    # fields: frame.time_epoch, ip.src, frame.len, (tcp.len OR udp.length)
    
    # We need to know src IP to separate Fwd/Bwd
    # Flow 1 Src: 192.168.137.102
    # Flow 2 Src: 192.168.137.49
    # Flow 3 Src: 192.168.137.72
    
    flow_src_map = {
        "flow1": "192.168.137.102",
        "flow2": "192.168.137.49",
        "flow3": "192.168.137.72"
    }
    src_ip_target = flow_src_map[name]
    
    fwd_pkts = 0
    bwd_pkts = 0
    fwd_bytes = 0
    bwd_bytes = 0
    fwd_lens = []
    bwd_lens = []
    
    large_pkts = 0
    medium_pkts = 0
    small_pkts = 0
    
    for line in lines:
        parts = line.strip().split('\t')
        if len(parts) < 3: continue
        
        ts = float(parts[0])
        src = parts[1]
        length = int(parts[2])
        
        timestamps.append(ts)
        frame_lens.append(length)
        
        # Direction
        if src == src_ip_target:
            fwd_pkts += 1
            fwd_bytes += length
            fwd_lens.append(length)
        else:
            bwd_pkts += 1
            bwd_bytes += length
            bwd_lens.append(length)
            
        # Size Categories
        if length > 600:
            large_pkts += 1
        elif length >= 400:
            medium_pkts += 1
        else:
            small_pkts += 1
            
    # Calculations
    duration_sec = timestamps[-1] - timestamps[0]
    duration_ms = duration_sec * 1000
    
    total_pkts = fwd_pkts + bwd_pkts
    
    # Ratios
    l_ratio = large_pkts / total_pkts if total_pkts > 0 else 0
    m_ratio = medium_pkts / total_pkts if total_pkts > 0 else 0
    s_ratio = small_pkts / total_pkts if total_pkts > 0 else 0
    
    # Means
    fwd_mean = statistics.mean(fwd_lens) if fwd_lens else 0
    bwd_mean = statistics.mean(bwd_lens) if bwd_lens else 0

    # Verification Print
    row = csv_rows[name]
    
    print(f"{'Feature':<25} | {'CSV Value':<15} | {'PCAP Calc':<15} | {'Match?'}")
    print("-" * 70)
    
    check_metric("Total Fwd Pkts", row['total_fwd_packets'], fwd_pkts)
    check_metric("Total Bwd Pkts", row['total_bwd_packets'], bwd_pkts)
    check_metric("Total Fwd Bytes", row['total_fwd_bytes'], fwd_bytes)
    check_metric("Total Bwd Bytes", row['total_bwd_bytes'], bwd_bytes)
    check_metric("Fwd Mean Len", row['fwd_packet_length_mean'], fwd_mean, tolerance=0.1)
    
    if "bwd_packet_length_mean" in row:
        check_metric("Bwd Mean Len", row['bwd_packet_length_mean'], bwd_mean, tolerance=0.1)
        
    check_metric("Large Pkt Ratio", row['large_packet_ratio'], l_ratio, tolerance=0.01)
    check_metric("Small Pkt Ratio", row['small_packet_ratio'], s_ratio, tolerance=0.01)
    
    # Duration: allow 1-2 ms diff due to double precision
    # Actually wait, CSV duration is exactly Long(last - first). 
    # But Tshark epoch is double.
    # Convert Tshark duration to ms and round.
    check_metric("Duration (ms)", row['flow_duration'], duration_ms, tolerance=50.0)

def check_metric(name, csv_val, calc_val, tolerance=0.0):
    diff = abs(csv_val - calc_val)
    match = diff <= tolerance
    mark = "PASS" if match else "FAIL"
    print(f"{name:<25} | {csv_val:<15} | {calc_val:<15.4f} | {mark}")

if __name__ == "__main__":
    analyze_flow("flow1")
    analyze_flow("flow2")
    analyze_flow("flow3")
