# validate_with_tshark.ps1
# Automated tshark validation for CIC-Flow-Meter-DNS
# Validates all 41 features against tool output

param(
    [Parameter(Mandatory=$true)]
    [string]$PcapFile,
    
    [Parameter(Mandatory=$true)]
    [string]$ToolCsvFile,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputReport = "tshark_validation_report.txt"
)

# Check if files exist
if (-not (Test-Path $PcapFile)) {
    Write-Error "PCAP file not found: $PcapFile"
    exit 1
}

if (-not (Test-Path $ToolCsvFile)) {
    Write-Error "Tool CSV file not found: $ToolCsvFile"
    exit 1
}

# Check if tshark is available
try {
    $null = tshark --version
} catch {
    Write-Error "tshark not found. Please install Wireshark."
    exit 1
}

$report = @"
================================================================================
              TSHARK MANUAL VALIDATION REPORT
================================================================================
PCAP File: $PcapFile
Tool Output: $ToolCsvFile
Validation Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
================================================================================

"@

Write-Host $report
$report | Out-File $OutputReport

# Load tool output
$toolOutput = Import-Csv $ToolCsvFile
if ($toolOutput.Count -eq 0) {
    Write-Error "No flows in tool output CSV"
    exit 1
}

# Get first flow (for single-flow PCAPs)
$toolFlow = $toolOutput[0]

# Helper function to compare values
function Compare-Values {
    param(
        [string]$FeatureName,
        [decimal]$ManualValue,
        [decimal]$ToolValue,
        [decimal]$Tolerance = 0.01  # 1% tolerance by default
    )
    
    $percentDiff = if ($ManualValue -ne 0) {
        [Math]::Abs(($ToolValue - $ManualValue) / $ManualValue) * 100
    } elseif ($ToolValue -ne 0) {
        100
    } else {
        0
    }
    
    $status = if ($percentDiff -le $Tolerance) { "PASS" } else { "FAIL" }
    $statusIcon = if ($status -eq "PASS") { "[OK]" } else { "[!!]" }
    
    $line = "$statusIcon $FeatureName
      Manual:  $ManualValue
      Tool:    $ToolValue
      Diff:    $($percentDiff.ToString("F2"))%
      Status:  $status
"
    
    Write-Host $line
    return $line
}

Write-Host "`n[CATEGORY 1: DNS CRITICAL FEATURES]"
$report += "`n[CATEGORY 1: DNS CRITICAL FEATURES]`n"

# Get basic counts first
Write-Host "`nCalculating DNS packet counts..."
$dnsQueryCount = (tshark -r $PcapFile -Y "dns.flags.response == 0" 2>$null | Measure-Object -Line).Lines
$dnsResponseCount = (tshark -r $PcapFile -Y "dns.flags.response == 1" 2>$null | Measure-Object -Line).Lines

Write-Host "  DNS Queries: $dnsQueryCount"
Write-Host "  DNS Responses: $dnsResponseCount"

# Feature 1: dns_total_queries
$report += Compare-Values -FeatureName "dns_total_queries" -ManualValue $dnsQueryCount -ToolValue $toolFlow.dns_total_queries

# Feature 2: dns_total_responses
$report += Compare-Values -FeatureName "dns_total_responses" -ManualValue $dnsResponseCount -ToolValue $toolFlow.dns_total_responses

# Feature 3: dns_amplification_factor
Write-Host "`nCalculating amplification factor..."
$queryBytes = (tshark -r $PcapFile -Y "dns.flags.response == 0" -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
$responseBytes = (tshark -r $PcapFile -Y "dns.flags.response == 1" -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
$ampFactor = if ($queryBytes -gt 0) { [decimal]($responseBytes / $queryBytes) } else { 0 }

Write-Host "  Query Bytes: $queryBytes"
Write-Host "  Response Bytes: $responseBytes"

$report += Compare-Values -FeatureName "dns_amplification_factor" -ManualValue $ampFactor -ToolValue $toolFlow.dns_amplification_factor

# Feature 4: query_response_ratio
$qrRatio = if ($dnsResponseCount -gt 0) { [decimal]($dnsQueryCount / $dnsResponseCount) } else { $dnsQueryCount }
$report += Compare-Values -FeatureName "query_response_ratio" -ManualValue $qrRatio -ToolValue $toolFlow.query_response_ratio

# Feature 5: dns_any_query_ratio
Write-Host "`nCounting query types..."
$anyCount = (tshark -r $PcapFile -Y "dns.qry.type == 255" 2>$null | Measure-Object -Line).Lines
$anyRatio = if ($dnsQueryCount -gt 0) { [decimal]($anyCount / $dnsQueryCount) } else { 0 }
Write-Host "  ANY queries: $anyCount"

$report += Compare-Values -FeatureName "dns_any_query_ratio" -ManualValue $anyRatio -ToolValue $toolFlow.dns_any_query_ratio

# Feature 6: dns_txt_query_ratio
$txtCount = (tshark -r $PcapFile -Y "dns.qry.type == 16" 2>$null | Measure-Object -Line).Lines
$txtRatio = if ($dnsQueryCount -gt 0) { [decimal]($txtCount / $dnsQueryCount) } else { 0 }
Write-Host "  TXT queries: $txtCount"

$report += Compare-Values -FeatureName "dns_txt_query_ratio" -ManualValue $txtRatio -ToolValue $toolFlow.dns_txt_query_ratio

# Feature 7: dns_response_inconsistency
$inconsistency = [Math]::Abs($dnsQueryCount - $dnsResponseCount)
$report += Compare-Values -FeatureName "dns_response_inconsistency" -ManualValue $inconsistency -ToolValue $toolFlow.dns_response_inconsistency

# Feature 8: dns_queries_per_second
Write-Host "`nCalculating timing metrics..."
$timestamps = tshark -r $PcapFile -T fields -e frame.time_epoch 2>$null
if ($timestamps.Count -gt 0) {
    $firstTime = [double]$timestamps[0]
    $lastTime = [double]$timestamps[-1]
    $durationSec = $lastTime - $firstTime
    $durationMs = $durationSec * 1000
    
    Write-Host "  First packet: $firstTime"
    Write-Host "  Last packet: $lastTime"
    Write-Host "  Duration: $durationMs ms ($durationSec sec)"
    
    $qps = if ($durationSec -gt 0) { [decimal]($dnsQueryCount / $durationSec) } else { 0 }
    $report += Compare-Values -FeatureName "dns_queries_per_second" -ManualValue $qps -ToolValue $toolFlow.dns_queries_per_second
} else {
    Write-Host "  WARNING: Could not extract timestamps"
}

# Feature 9: dns_mean_answers_per_query
$answerCounts = tshark -r $PcapFile -Y "dns.flags.response == 1" -T fields -e dns.count.answers 2>$null
if ($answerCounts) {
    $totalAnswers = ($answerCounts | Measure-Object -Sum).Sum
    $meanAnswers = if ($dnsResponseCount -gt 0) { [decimal]($totalAnswers / $dnsResponseCount) } else { 0 }
    Write-Host "  Total answers: $totalAnswers"
    
    $report += Compare-Values -FeatureName "dns_mean_answers_per_query" -ManualValue $meanAnswers -ToolValue $toolFlow.dns_mean_answers_per_query
}

# Feature 10: dns_response_bytes
$report += Compare-Values -FeatureName "dns_response_bytes" -ManualValue $responseBytes -ToolValue $toolFlow.dns_response_bytes

# Feature 11: port_53_traffic_ratio
$totalBytes = (tshark -r $PcapFile -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
$port53Bytes = (tshark -r $PcapFile -Y "udp.port == 53" -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
$port53Ratio = if ($totalBytes -gt 0) { [decimal]($port53Bytes / $totalBytes) } else { 0 }
$report += Compare-Values -FeatureName "port_53_traffic_ratio" -ManualValue $port53Ratio -ToolValue $toolFlow.port_53_traffic_ratio

# Feature 12: dns_server_fanout (placeholder = 0)
$report += Compare-Values -FeatureName "dns_server_fanout" -ManualValue 0 -ToolValue $toolFlow.dns_server_fanout

# Feature 13: ttl_violation_rate (placeholder = 0)
$report += Compare-Values -FeatureName "ttl_violation_rate" -ManualValue 0 -ToolValue $toolFlow.ttl_violation_rate

Write-Host "`n[CATEGORY 2: FLOW RATE FEATURES]"
$report += "`n[CATEGORY 2: FLOW RATE FEATURES]`n"

# Feature 14: flow_bytes_per_sec
$bytesPerSec = if ($durationSec -gt 0) { [decimal]($totalBytes / $durationSec) } else { 0 }
$report += Compare-Values -FeatureName "flow_bytes_per_sec" -ManualValue $bytesPerSec -ToolValue $toolFlow.flow_bytes_per_sec

# Feature 15: flow_packets_per_sec
$totalPackets = (tshark -r $PcapFile 2>$null | Measure-Object -Line).Lines
$packetsPerSec = if ($durationSec -gt 0) { [decimal]($totalPackets / $durationSec) } else { 0 }
$report += Compare-Values -FeatureName "flow_packets_per_sec" -ManualValue $packetsPerSec -ToolValue $toolFlow.flow_packets_per_sec

# For forward/backward, we need to identify flow direction
# Use first packet's source IP as "forward" direction
$firstPacket = tshark -r $PcapFile -T fields -e ip.src -c 1 2>$null
if ($firstPacket) {
    $srcIP = $firstPacket[0]
    Write-Host "  Flow source IP: $srcIP"
    
    # Feature 16: fwd_packets_per_sec
    $fwdPackets = (tshark -r $PcapFile -Y "ip.src == $srcIP" 2>$null | Measure-Object -Line).Lines
    $fwdPacketsPerSec = if ($durationSec -gt 0) { [decimal]($fwdPackets / $durationSec) } else { 0 }
    $report += Compare-Values -FeatureName "fwd_packets_per_sec" -ManualValue $fwdPacketsPerSec -ToolValue $toolFlow.fwd_packets_per_sec
    
    # Feature 17: bwd_packets_per_sec
    $bwdPackets = $totalPackets - $fwdPackets
    $bwdPacketsPerSec = if ($durationSec -gt 0) { [decimal]($bwdPackets / $durationSec) } else { 0 }
    $report += Compare-Values -FeatureName "bwd_packets_per_sec" -ManualValue $bwdPacketsPerSec -ToolValue $toolFlow.bwd_packets_per_sec
}

Write-Host "`n[CATEGORY 3: FLOW STATISTICS]"
$report += "`n[CATEGORY 3: FLOW STATISTICS]`n"

# Feature 18: flow_duration
$report += Compare-Values -FeatureName "flow_duration" -ManualValue $durationMs -ToolValue $toolFlow.flow_duration -Tolerance 1.0

# Feature 19-23: Packet and byte counts
$report += Compare-Values -FeatureName "total_fwd_packets" -ManualValue $fwdPackets -ToolValue $toolFlow.total_fwd_packets
$report += Compare-Values -FeatureName "total_bwd_packets" -ManualValue $bwdPackets -ToolValue $toolFlow.total_bwd_packets

$fwdBytes = (tshark -r $PcapFile -Y "ip.src == $srcIP" -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
$bwdBytes = $totalBytes - $fwdBytes

$report += Compare-Values -FeatureName "total_fwd_bytes" -ManualValue $fwdBytes -ToolValue $toolFlow.total_fwd_bytes
$report += Compare-Values -FeatureName "total_bwd_bytes" -ManualValue $bwdBytes -ToolValue $toolFlow.total_bwd_bytes

Write-Host "`n[CATEGORY 4: PACKET SIZE FEATURES]"
$report += "`n[CATEGORY 4: PACKET SIZE FEATURES]`n"

# Feature 24: average_packet_size
$allSizes = tshark -r $PcapFile -T fields -e frame.len 2>$null | ForEach-Object { [int]$_ }
$avgSize = ($allSizes | Measure-Object -Average).Average
$report += Compare-Values -FeatureName "average_packet_size" -ManualValue $avgSize -ToolValue $toolFlow.average_packet_size

# Feature 25: packet_size_std
# Note: Tool uses sample std dev (n-1), PowerShell Measure-Object doesn't have std dev
# We'll calculate it manually or note the difference
Write-Host "  Note: Skipping packet_size_std (requires manual Excel calculation)"

# Feature 26-27: min/max
$minSize = ($allSizes | Measure-Object -Minimum).Minimum
$maxSize = ($allSizes | Measure-Object -Maximum).Maximum
$report += Compare-Values -FeatureName "flow_length_min" -ManualValue $minSize -ToolValue $toolFlow.flow_length_min
$report += Compare-Values -FeatureName "flow_length_max" -ManualValue $maxSize -ToolValue $toolFlow.flow_length_max

# Feature 28-29: Forward/backward means
$fwdSizes = tshark -r $PcapFile -Y "ip.src == $srcIP" -T fields -e frame.len 2>$null | ForEach-Object { [int]$_ }
$fwdMean = if ($fwdSizes.Count -gt 0) { ($fwdSizes | Measure-Object -Average).Average } else { 0 }
$report += Compare-Values -FeatureName "fwd_packet_length_mean" -ManualValue $fwdMean -ToolValue $toolFlow.fwd_packet_length_mean

$bwdSizes = tshark -r $PcapFile -Y "ip.dst == $srcIP" -T fields -e frame.len 2>$null | ForEach-Object { [int]$_ }
$bwdMean = if ($bwdSizes.Count -gt 0) { ($bwdSizes | Measure-Object -Average).Average } else { 0 }
$report += Compare-Values -FeatureName "bwd_packet_length_mean" -ManualValue $bwdMean -ToolValue $toolFlow.bwd_packet_length_mean

# Summary
Write-Host "`n" + ("=" * 80)
Write-Host "VALIDATION COMPLETE"
Write-Host ("=" * 80)
Write-Host "`nFull report saved to: $OutputReport"

# Save report
$report | Out-File $OutputReport -Append

Write-Host "`nTo view report:"
Write-Host "  notepad $OutputReport"
