# -*- coding: utf-8 -*-
"""
Automated DNS Feature Validation Test
Runs a controlled test to verify DNS feature extraction
"""
import subprocess
import time
import sys
import os

def run_capture_tool():
    """Start the CIC-Flow-Meter tool in background"""
    print("[*] Starting CIC-Flow-Meter capture tool...")
    
    jar_path = r"C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\target\net-traffic-analysis-1.0-SNAPSHOT.jar"
    output_file = r"C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\validation_test.csv"
    
    # Remove old test file if exists
    if os.path.exists(output_file):
        os.remove(output_file)
        print("[+] Removed old test file")
    
    cmd = [
        "java",
        "-jar",
        jar_path,
        "--pcap", "live",
        "--output", output_file,
        "--timeout", "120000"  # 2 minute timeout
    ]
    
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
    )
    
    print(f"[+] Capture tool started (PID: {process.pid})")
    print(f"[+] Output file: {output_file}")
    
    return process, output_file

def run_attack():
    """Run DNS amplification attack"""
    print("\n[*] Starting DNS Amplification Attack...")
    print("    Attack Type: 2 (DNS Amplification)")
    print("    Duration: 20 seconds")
    print("    Rate: 100 QPS")
    print("    Query Types: ANY (255), TXT (16), MX (15)")
    
    # Create input for the attack script
    attack_input = "127.0.0.1\n2\n20\n"
    
    attack_script = r"C:\Users\shenal\Downloads\reseraach\CIC-Flow-Meter-DNS\generate_attack_dns.py"
    
    try:
        result = subprocess.run(
            ["python", attack_script],
            input=attack_input,
            text=True,
            capture_output=True,
            timeout=60
        )
        
        print("\n[+] Attack completed")
        if result.returncode == 0:
            print("[+] Attack script executed successfully")
        else:
            print(f"[!] Attack script returned code: {result.returncode}")
            if result.stderr:
                print(f"    Error: {result.stderr[:200]}")
       
        return True
    except subprocess.TimeoutExpired:
        print("[!] Attack script timed out (expected for some scenarios)")
        return True
    except Exception as e:
        print(f"[X] Attack failed: {e}")
        return False

def stop_capture(process):
    """Stop the capture tool"""
    print("\n[*] Stopping capture tool...")
    
    try:
        process.terminate()
        process.wait(timeout=10)
        print("[+] Capture tool stopped gracefully")
    except subprocess.TimeoutExpired:
        process.kill()
        print("[+] Capture tool force-stopped")
    except Exception as e:
        print(f"[!] Error stopping capture: {e}")

def analyze_results(csv_file):
    """Analyze the captured CSV for DNS features"""
    print(f"\n[*] Analyzing results from: {csv_file}")
    
    if not os.path.exists(csv_file):
        print("[X] Output file not found!")
        return False
    
    file_size = os.path.getsize(csv_file)
    print(f"[+] File size: {file_size:,} bytes")
    
    try:
        with open(csv_file, 'r') as f:
            lines = f.readlines()
            
        if len(lines) < 2:
            print("[X] No data captured (only header or empty)")
            return False
        
        print(f"[+] Total flows captured: {len(lines) - 1}")
        
        # Parse header
        header = lines[0].strip().split(',')
        
        # Find column indices
        try:
            idx_any_ratio = header.index('dns_any_query_ratio')
            idx_txt_ratio = header.index('dns_txt_query_ratio')
            idx_server_fanout = header.index('dns_server_fanout')
            idx_ttl_violation = header.index('ttl_violation_rate')
            idx_dns_queries = header.index('dns_total_queries')
            idx_dns_responses = header.index('dns_total_responses')
        except ValueError as e:
            print(f"[X] Column not found: {e}")
            return False
        
        # Analyze data rows
        print("\n" + "=" * 70)
        print("VALIDATION RESULTS")
        print("=" * 70)
        
        any_ratio_values = []
        txt_ratio_values = []
        dns_queries_values = []
        
        for i, line in enumerate(lines[1:], 1):
            cols = line.strip().split(',')
            if len(cols) <= max(idx_any_ratio, idx_txt_ratio, idx_dns_queries):
                continue
            
            try:
                any_ratio = float(cols[idx_any_ratio])
                txt_ratio = float(cols[idx_txt_ratio])
                dns_queries = int(cols[idx_dns_queries])
                dns_responses = int(cols[idx_dns_responses])
                
                any_ratio_values.append(any_ratio)
                txt_ratio_values.append(txt_ratio)
                dns_queries_values.append(dns_queries)
                
                if i <= 5:  # Show first 5 flows
                    print(f"\nFlow {i}:")
                    print(f"  dns_any_query_ratio:     {any_ratio:.4f}")
                    print(f"  dns_txt_query_ratio:     {txt_ratio:.4f}")
                    print(f"  dns_total_queries:       {dns_queries}")
                    print(f"  dns_total_responses:     {dns_responses}")
                    print(f"  dns_server_fanout:       {cols[idx_server_fanout]}")
                    print(f"  ttl_violation_rate:      {cols[idx_ttl_violation]}")
            except (ValueError, IndexError):
                continue
        
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        
        # Summary statistics
        if any_ratio_values:
            non_zero_any = sum(1 for x in any_ratio_values if x > 0)
            non_zero_txt = sum(1 for x in txt_ratio_values if x > 0)
            total_dns_flows = sum(1 for x in dns_queries_values if x > 0)
            
            print(f"Total flows analyzed: {len(any_ratio_values)}")
            print(f"DNS flows detected: {total_dns_flows}")
            print(f"\n[+] dns_any_query_ratio:")
            print(f"    - Non-zero values: {non_zero_any}/{len(any_ratio_values)}")
            print(f"    - Max value: {max(any_ratio_values):.4f}")
            
            print(f"\n[+] dns_txt_query_ratio:")
            print(f"    - Non-zero values: {non_zero_txt}/{len(any_ratio_values)}")
            print(f"    - Max value: {max(txt_ratio_values):.4f}")
            
            # Verdict
            print("\n" + "=" * 70)
            if non_zero_any > 0 or non_zero_txt > 0:
                print("[SUCCESS] VALIDATION PASSED!")
                print("          The tool IS correctly extracting DNS query type ratios.")
            else:
                print("[FAILED] VALIDATION FAILED!")
                print("         The tool is NOT capturing ANY/TXT query ratios.")
                print("         This confirms there's an issue with feature extraction.")
            print("=" * 70)
            
            return non_zero_any > 0 or non_zero_txt > 0
        else:
            print("[X] No valid data to analyze")
            return False
            
    except Exception as e:
        print(f"[X] Analysis error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("""
================================================================
     DNS FEATURE EXTRACTION VALIDATION TEST
================================================================
  This will:
    1. Start CIC-Flow-Meter capture
    2. Run DNS amplification attack (20 sec)
    3. Analyze captured data
================================================================
""")

    
    # Step 1: Start capture
    capture_process, output_file = run_capture_tool()
    
    try:
        # Wait for tool to initialize
        print("\n[*] Waiting 5 seconds for capture tool to initialize...")
        time.sleep(5)
        
        # Step 2: Run attack
        attack_success = run_attack()
        
        if not attack_success:
            print("[X] Attack failed! Stopping...")
            stop_capture(capture_process)
            return 1
        
        # Wait for flows to be written
        print("\n[*] Waiting 10 seconds for flows to be exported...")
        time.sleep(10)
        
        # Step 3: Stop capture
        stop_capture(capture_process)
        
        # Step 4: Analyze results
        time.sleep(2)  # Brief pause before reading file
        success = analyze_results(output_file)
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n\n[!] Test interrupted by user")
        stop_capture(capture_process)
        return 1
    except Exception as e:
        print(f"\n[X] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        stop_capture(capture_process)
        return 1

if __name__ == '__main__':
    sys.exit(main())
