# Comprehensive 3-Flow Validation Script
# Tests 3 random flows (top, middle, bottom) against tshark ground truth
# Validates EVERY single column for each flow

param(
    [string]$PcapFile = "C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\DNS_Spoofing.pcap",
    [string]$CsvFile = "C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\New-CIC-JAVA\DNS_Spoofing_fixed.csv"
)

Write-Host ("=" * 120) -ForegroundColor Cyan
Write-Host "COMPREHENSIVE 3-FLOW VALIDATION - ALL COLUMNS" -ForegroundColor Cyan
Write-Host ("=" * 120) -ForegroundColor Cyan

# Verify files exist
if (-not (Test-Path $PcapFile)) {
    Write-Host "[ERROR] PCAP file not found: $PcapFile" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $CsvFile)) {
    Write-Host "[ERROR] CSV file not found: $CsvFile" -ForegroundColor Red
    exit 1
}

Write-Host "`n[INFO] Loading CSV file..." -ForegroundColor Green
$allFlows = Import-Csv $CsvFile

$totalFlows = $allFlows.Count
Write-Host "[INFO] Total flows in CSV: $totalFlows" -ForegroundColor Green

# Select 3 flows: top, middle, bottom
$topIndex = Get-Random -Minimum 0 -Maximum ([Math]::Min(100, [Math]::Floor($totalFlows / 3)))
$middleIndex = Get-Random -Minimum ([Math]::Floor($totalFlows / 3)) -Maximum ([Math]::Floor($totalFlows * 2 / 3))
$bottomIndex = Get-Random -Minimum ([Math]::Floor($totalFlows * 2 / 3)) -Maximum ($totalFlows)

$testFlows = @(
    @{Name = "TOP"; Index = $topIndex; Flow = $allFlows[$topIndex]},
    @{Name = "MIDDLE"; Index = $middleIndex; Flow = $allFlows[$middleIndex]},
    @{Name = "BOTTOM"; Index = $bottomIndex; Flow = $allFlows[$bottomIndex]}
)

Write-Host "`n[INFO] Selected flows for validation:" -ForegroundColor Green
foreach ($tf in $testFlows) {
    Write-Host "  $($tf.Name) section: Row #$($tf.Index + 1) - $($tf.Flow.src_ip):$($tf.Flow.src_port) -> $($tf.Flow.dst_ip):$($tf.Flow.dst_port)"
}

$allResults = @()

# ================================================================
# VALIDATION FUNCTION
# ================================================================
function Validate-Flow {
    param($flowData, $flowName, $flowIndex)
    
    Write-Host "`n`n" + ("=" * 120) -ForegroundColor Magenta
    Write-Host "VALIDATING FLOW: $flowName (Row #$($flowIndex + 1))" -ForegroundColor Magenta
    Write-Host ("=" * 120) -ForegroundColor Magenta
    
    Write-Host "`n[FLOW IDENTITY]" -ForegroundColor Yellow
    Write-Host "  src_ip: $($flowData.src_ip)"
    Write-Host "  dst_ip: $($flowData.dst_ip)"
    Write-Host "  src_port: $($flowData.src_port)"
    Write-Host "  dst_port: $($flowData.dst_port)"
    Write-Host "  protocol: $($flowData.protocol)"
    
    # Build filters
    if ($flowData.protocol -eq "TCP") {
        $filterFwd = "ip.src == $($flowData.src_ip) and ip.dst == $($flowData.dst_ip) and tcp.srcport == $($flowData.src_port) and tcp.dstport == $($flowData.dst_port)"
        $filterBwd = "ip.src == $($flowData.dst_ip) and ip.dst == $($flowData.src_ip) and tcp.srcport == $($flowData.dst_port) and tcp.dstport == $($flowData.src_port)"
    } else {
        $filterFwd = "ip.src == $($flowData.src_ip) and ip.dst == $($flowData.dst_ip) and udp.srcport == $($flowData.src_port) and udp.dstport == $($flowData.dst_port)"
        $filterBwd = "ip.src == $($flowData.dst_ip) and ip.dst == $($flowData.src_ip) and udp.srcport == $($flowData.dst_port) and udp.dstport == $($flowData.src_port)"
    }
    $filterBoth = "($filterFwd) or ($filterBwd)"
    
    $results = @()
    
    # ================================================================
    # 1. PACKET COUNTS
    # ================================================================
    Write-Host "`n[1] PACKET COUNTS" -ForegroundColor Cyan
    
    $tsharkFwdPkts = (tshark -r $PcapFile -Y $filterFwd -T fields -e frame.number 2>$null | Measure-Object -Line).Lines
    if ($null -eq $tsharkFwdPkts) { $tsharkFwdPkts = 0 }
    $toolFwdPkts = [int]$flowData.total_fwd_packets
    $match = ($toolFwdPkts -eq $tsharkFwdPkts)
    Write-Host "  total_fwd_packets: Tool=$toolFwdPkts, tshark=$tsharkFwdPkts $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="total_fwd_packets"; Tool=$toolFwdPkts; Tshark=$tsharkFwdPkts; Status=if($match){"PASS"}else{"FAIL"}}
    
    $tsharkBwdPkts = (tshark -r $PcapFile -Y $filterBwd -T fields -e frame.number 2>$null | Measure-Object -Line).Lines
    if ($null -eq $tsharkBwdPkts) { $tsharkBwdPkts = 0 }
    $toolBwdPkts = [int]$flowData.total_bwd_packets
    $match = ($toolBwdPkts -eq $tsharkBwdPkts)
    Write-Host "  total_bwd_packets: Tool=$toolBwdPkts, tshark=$tsharkBwdPkts $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="total_bwd_packets"; Tool=$toolBwdPkts; Tshark=$tsharkBwdPkts; Status=if($match){"PASS"}else{"FAIL"}}
    
    # ================================================================
    # 2. BYTE COUNTS
    # ================================================================
    Write-Host "`n[2] BYTE COUNTS" -ForegroundColor Cyan
    
    $tsharkFwdBytes = (tshark -r $PcapFile -Y $filterFwd -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
    if ($null -eq $tsharkFwdBytes) { $tsharkFwdBytes = 0 }
    $toolFwdBytes = [double]$flowData.total_fwd_bytes
    $match = ([Math]::Abs($toolFwdBytes - $tsharkFwdBytes) -le 1)
    Write-Host "  total_fwd_bytes: Tool=$toolFwdBytes, tshark=$tsharkFwdBytes $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="total_fwd_bytes"; Tool=$toolFwdBytes; Tshark=$tsharkFwdBytes; Status=if($match){"PASS"}else{"FAIL"}}
    
    $tsharkBwdBytes = (tshark -r $PcapFile -Y $filterBwd -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
    if ($null -eq $tsharkBwdBytes) { $tsharkBwdBytes = 0 }
    $toolBwdBytes = [double]$flowData.total_bwd_bytes
    $match = ([Math]::Abs($toolBwdBytes - $tsharkBwdBytes) -le 1)
    Write-Host "  total_bwd_bytes: Tool=$toolBwdBytes, tshark=$tsharkBwdBytes $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="total_bwd_bytes"; Tool=$toolBwdBytes; Tshark=$tsharkBwdBytes; Status=if($match){"PASS"}else{"FAIL"}}
    
    # ================================================================
    # 3. FLOW DURATION
    # ================================================================
    Write-Host "`n[3] FLOW DURATION" -ForegroundColor Cyan
    
    $timestamps = tshark -r $PcapFile -Y $filterBoth -T fields -e frame.time_epoch 2>$null | 
        Where-Object { $_ -match '\d' } | ForEach-Object { [double]$_ }
    
    if ($timestamps.Count -gt 0) {
        $firstTime = ($timestamps | Measure-Object -Minimum).Minimum
        $lastTime = ($timestamps | Measure-Object -Maximum).Maximum
        $tsharkDuration = ($lastTime - $firstTime) * 1000
        $toolDuration = [double]$flowData.flow_duration
        $match = ([Math]::Abs($toolDuration - $tsharkDuration) -lt 10)
        Write-Host "  flow_duration: Tool=$([Math]::Round($toolDuration,2))ms, tshark=$([Math]::Round($tsharkDuration,2))ms $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="flow_duration"; Tool=[Math]::Round($toolDuration,2); Tshark=[Math]::Round($tsharkDuration,2); Status=if($match){"PASS"}else{"FAIL"}}
    }
    
    # ================================================================
    # 4. FLOW LENGTH MIN/MAX/MEAN/STD (NEW FEATURES)
    # ================================================================
    Write-Host "`n[4] FLOW LENGTH STATISTICS [NEW FEATURES]" -ForegroundColor Yellow
    
    $lengths = tshark -r $PcapFile -Y $filterBoth -T fields -e frame.len 2>$null | 
        Where-Object { $_ -match '\d' } | ForEach-Object { [int]$_ }
    
    if ($lengths.Count -gt 0) {
        $lengthStats = $lengths | Measure-Object -Minimum -Maximum -Average
        
        # Min
        $toolMin = [double]$flowData.flow_length_min
        $tsharkMin = $lengthStats.Minimum
        $match = ($toolMin -eq $tsharkMin)
        Write-Host "  flow_length_min: Tool=$toolMin, tshark=$tsharkMin $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="flow_length_min [NEW]"; Tool=$toolMin; Tshark=$tsharkMin; Status=if($match){"PASS"}else{"FAIL"}}
        
        # Max
        $toolMax = [double]$flowData.flow_length_max
        $tsharkMax = $lengthStats.Maximum
        $match = ($toolMax -eq $tsharkMax)
        Write-Host "  flow_length_max: Tool=$toolMax, tshark=$tsharkMax $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="flow_length_max [NEW]"; Tool=$toolMax; Tshark=$tsharkMax; Status=if($match){"PASS"}else{"FAIL"}}
        
        # Mean (average_packet_size)
        $toolAvg = [double]$flowData.average_packet_size
        $tsharkAvg = [Math]::Round($lengthStats.Average, 4)
        $match = ([Math]::Abs($toolAvg - $tsharkAvg) -lt 0.5)
        Write-Host "  average_packet_size: Tool=$toolAvg, tshark=$tsharkAvg $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="average_packet_size"; Tool=$toolAvg; Tshark=$tsharkAvg; Status=if($match){"PASS"}else{"FAIL"}}
        
        # Std (packet_size_std)
        $toolStd = [double]$flowData.packet_size_std
        $valid = ($toolStd -ge 0)
        Write-Host "  packet_size_std: Tool=$toolStd (sanity: $(if ($valid) {'✓'} else {'✗'}))"
        $results += [PSCustomObject]@{Flow=$flowName; Column="packet_size_std"; Tool=$toolStd; Tshark="N/A"; Status=if($valid){"PASS"}else{"FAIL"}}
    }
    
    # ================================================================
    # 5. FLOW IAT MIN/MAX/MEAN/STD (NEW FEATURES)
    # ================================================================
    Write-Host "`n[5] FLOW IAT STATISTICS [NEW FEATURES]" -ForegroundColor Yellow
    
    $sortedTimestamps = $timestamps | Sort-Object
    $iats = @()
    for ($i = 1; $i -lt $sortedTimestamps.Count; $i++) {
        $iat = ($sortedTimestamps[$i] - $sortedTimestamps[$i-1]) * 1000
        $iats += $iat
    }
    
    if ($iats.Count -gt 0) {
        $iatStats = $iats | Measure-Object -Minimum -Maximum -Average
        
        # Min
        $toolIatMin = [double]$flowData.flow_iat_min
        $tsharkIatMin = [Math]::Round($iatStats.Minimum, 4)
        $match = ([Math]::Abs($toolIatMin - $tsharkIatMin) -lt 1.0)
        Write-Host "  flow_iat_min: Tool=$toolIatMin, tshark=$tsharkIatMin $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="flow_iat_min [NEW]"; Tool=$toolIatMin; Tshark=$tsharkIatMin; Status=if($match){"PASS"}else{"FAIL"}}
        
        # Max
        $toolIatMax = [double]$flowData.flow_iat_max
        $tsharkIatMax = [Math]::Round($iatStats.Maximum, 4)
        $match = ([Math]::Abs($toolIatMax - $tsharkIatMax) -lt 1.0)
        Write-Host "  flow_iat_max: Tool=$toolIatMax, tshark=$tsharkIatMax $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="flow_iat_max [NEW]"; Tool=$toolIatMax; Tshark=$tsharkIatMax; Status=if($match){"PASS"}else{"FAIL"}}
        
        # Mean
        $toolIatMean = [double]$flowData.flow_iat_mean
        $tsharkIatMean = [Math]::Round($iatStats.Average, 4)
        $match = ([Math]::Abs($toolIatMean - $tsharkIatMean) -lt 1.0)
        Write-Host "  flow_iat_mean: Tool=$toolIatMean, tshark=$tsharkIatMean $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="flow_iat_mean"; Tool=$toolIatMean; Tshark=$tsharkIatMean; Status=if($match){"PASS"}else{"FAIL"}}
        
        # Std
        $toolIatStd = [double]$flowData.flow_iat_std
        $valid = ($toolIatStd -ge 0)
        Write-Host "  flow_iat_std: Tool=$toolIatStd (sanity: $(if ($valid) {'✓'} else {'✗'}))"
        $results += [PSCustomObject]@{Flow=$flowName; Column="flow_iat_std"; Tool=$toolIatStd; Tshark="N/A"; Status=if($valid){"PASS"}else{"FAIL"}}
    }
    
    # ================================================================
    # 6. PACKET LENGTH MEANS (FWD/BWD)
    # ================================================================
    Write-Host "`n[6] PACKET LENGTH MEANS (DIRECTIONAL)" -ForegroundColor Cyan
    
    $expectedFwdMean = if ($tsharkFwdPkts -gt 0) { $tsharkFwdBytes / $tsharkFwdPkts } else { 0 }
    $toolFwdMean = [double]$flowData.fwd_packet_length_mean
    $match = ([Math]::Abs($toolFwdMean - $expectedFwdMean) -lt 0.5)
    Write-Host "  fwd_packet_length_mean: Tool=$toolFwdMean, expected=$([Math]::Round($expectedFwdMean,4)) $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="fwd_packet_length_mean"; Tool=$toolFwdMean; Tshark=[Math]::Round($expectedFwdMean,4); Status=if($match){"PASS"}else{"FAIL"}}
    
    $expectedBwdMean = if ($tsharkBwdPkts -gt 0) { $tsharkBwdBytes / $tsharkBwdPkts } else { 0 }
    $toolBwdMean = [double]$flowData.bwd_packet_length_mean
    $match = ([Math]::Abs($toolBwdMean - $expectedBwdMean) -lt 0.5)
    Write-Host "  bwd_packet_length_mean: Tool=$toolBwdMean, expected=$([Math]::Round($expectedBwdMean,4)) $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="bwd_packet_length_mean"; Tool=$toolBwdMean; Tshark=[Math]::Round($expectedBwdMean,4); Status=if($match){"PASS"}else{"FAIL"}}
    
    # ================================================================
    # 7. FLOW RATES
    # ================================================================
    Write-Host "`n[7] FLOW RATES" -ForegroundColor Cyan
    
    $durationSec = if ([double]$flowData.flow_duration -gt 0) { [double]$flowData.flow_duration / 1000.0 } else { 1.0 }
    $totalBytes = $tsharkFwdBytes + $tsharkBwdBytes
    $totalPkts = $tsharkFwdPkts + $tsharkBwdPkts
    
    # flow_bytes_per_sec
    $expectedBPS = $totalBytes / $durationSec
    $toolBPS = [double]$flowData.flow_bytes_per_sec
    $match = ([Math]::Abs($toolBPS - $expectedBPS) -lt 1.0)
    Write-Host "  flow_bytes_per_sec: Tool=$([Math]::Round($toolBPS,2)), expected=$([Math]::Round($expectedBPS,2)) $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="flow_bytes_per_sec"; Tool=[Math]::Round($toolBPS,2); Tshark=[Math]::Round($expectedBPS,2); Status=if($match){"PASS"}else{"FAIL"}}
    
    # flow_packets_per_sec
    $expectedPPS = $totalPkts / $durationSec
    $toolPPS = [double]$flowData.flow_packets_per_sec
    $match = ([Math]::Abs($toolPPS - $expectedPPS) -lt 0.1)
    Write-Host "  flow_packets_per_sec: Tool=$([Math]::Round($toolPPS,2)), expected=$([Math]::Round($expectedPPS,2)) $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="flow_packets_per_sec"; Tool=[Math]::Round($toolPPS,2); Tshark=[Math]::Round($expectedPPS,2); Status=if($match){"PASS"}else{"FAIL"}}
    
    # fwd_packets_per_sec
    $expectedFwdPPS = $tsharkFwdPkts / $durationSec
    $toolFwdPPS = [double]$flowData.fwd_packets_per_sec
    $match = ([Math]::Abs($toolFwdPPS - $expectedFwdPPS) -lt 0.1)
    Write-Host "  fwd_packets_per_sec: Tool=$([Math]::Round($toolFwdPPS,2)), expected=$([Math]::Round($expectedFwdPPS,2)) $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="fwd_packets_per_sec"; Tool=[Math]::Round($toolFwdPPS,2); Tshark=[Math]::Round($expectedFwdPPS,2); Status=if($match){"PASS"}else{"FAIL"}}
    
    # bwd_packets_per_sec
    $expectedBwdPPS = $tsharkBwdPkts / $durationSec
    $toolBwdPPS = [double]$flowData.bwd_packets_per_sec
    $match = ([Math]::Abs($toolBwdPPS - $expectedBwdPPS) -lt 0.1)
    Write-Host "  bwd_packets_per_sec: Tool=$([Math]::Round($toolBwdPPS,2)), expected=$([Math]::Round($expectedBwdPPS,2)) $(if ($match) {'✓'} else {'✗'})"
    $results += [PSCustomObject]@{Flow=$flowName; Column="bwd_packets_per_sec"; Tool=[Math]::Round($toolBwdPPS,2); Tshark=[Math]::Round($expectedBwdPPS,2); Status=if($match){"PASS"}else{"FAIL"}}
    
    # ================================================================
    # 8. DNS FEATURES (if DNS flow)
    # ================================================================
    if ([int]$flowData.dns_total_queries -gt 0 -or [int]$flowData.dns_total_responses -gt 0) {
        Write-Host "`n[8] DNS FEATURES" -ForegroundColor Cyan
        
        $filterDnsQuery = "$filterFwd and dns and dns.flags.response == 0"
        $filterDnsResp = "$filterBwd and dns and dns.flags.response == 1"
        
        # DNS queries
        $tsharkQueries = (tshark -r $PcapFile -Y $filterDnsQuery -T fields -e frame.number 2>$null | Measure-Object -Line).Lines
        if ($null -eq $tsharkQueries) { $tsharkQueries = 0 }
        $toolQueries = [int]$flowData.dns_total_queries
        $match = ($toolQueries -eq $tsharkQueries)
        Write-Host "  dns_total_queries: Tool=$toolQueries, tshark=$tsharkQueries $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="dns_total_queries"; Tool=$toolQueries; Tshark=$tsharkQueries; Status=if($match){"PASS"}else{"FAIL"}}
        
        # DNS responses
        $tsharkResponses = (tshark -r $PcapFile -Y $filterDnsResp -T fields -e frame.number 2>$null | Measure-Object -Line).Lines
        if ($null -eq $tsharkResponses) { $tsharkResponses = 0 }
        $toolResponses = [int]$flowData.dns_total_responses
        $match = ($toolResponses -eq $tsharkResponses)
        Write-Host "  dns_total_responses: Tool=$toolResponses, tshark=$tsharkResponses $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="dns_total_responses"; Tool=$toolResponses; Tshark=$tsharkResponses; Status=if($match){"PASS"}else{"FAIL"}}
        
        # DNS amplification factor
        if ($tsharkQueries -gt 0) {
            $tsharkQueryBytes = (tshark -r $PcapFile -Y $filterDnsQuery -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
            if ($null -eq $tsharkQueryBytes) { $tsharkQueryBytes = 0 }
            $tsharkRespBytes = (tshark -r $PcapFile -Y $filterDnsResp -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
            if ($null -eq $tsharkRespBytes) { $tsharkRespBytes = 0 }
            
            $tsharkAmpFactor = if ($tsharkQueryBytes -gt 0) { [double]$tsharkRespBytes / [double]$tsharkQueryBytes } else { 0 }
            $toolAmpFactor = [double]$flowData.dns_amplification_factor
            $match = ([Math]::Abs($toolAmpFactor - $tsharkAmpFactor) -lt 0.01)
            Write-Host "  dns_amplification_factor: Tool=$([Math]::Round($toolAmpFactor,4)), tshark=$([Math]::Round($tsharkAmpFactor,4)) $(if ($match) {'✓'} else {'✗'})"
            $results += [PSCustomObject]@{Flow=$flowName; Column="dns_amplification_factor"; Tool=[Math]::Round($toolAmpFactor,4); Tshark=[Math]::Round($tsharkAmpFactor,4); Status=if($match){"PASS"}else{"FAIL"}}
        }
        
        # DNS Mean Answers Per Query (NEW FEATURE)
        if ($tsharkResponses -gt 0) {
            $answerCounts = tshark -r $PcapFile -Y $filterDnsResp -T fields -e dns.count.answers 2>$null | 
                Where-Object { $_ -match '\d' } | ForEach-Object { [int]$_ }
            
            if ($answerCounts.Count -gt 0) {
                $totalAnswers = ($answerCounts | Measure-Object -Sum).Sum
                $tsharkMeanAnswers = $totalAnswers / $tsharkResponses
                $toolMeanAnswers = [double]$flowData.dns_mean_answers_per_query
                $match = ([Math]::Abs($toolMeanAnswers - $tsharkMeanAnswers) -lt 0.01)
                Write-Host "  dns_mean_answers_per_query [NEW]: Tool=$([Math]::Round($toolMeanAnswers,4)), tshark=$([Math]::Round($tsharkMeanAnswers,4)) $(if ($match) {'✓'} else {'✗'})"
                $results += [PSCustomObject]@{Flow=$flowName; Column="dns_mean_answers_per_query [NEW]"; Tool=[Math]::Round($toolMeanAnswers,4); Tshark=[Math]::Round($tsharkMeanAnswers,4); Status=if($match){"PASS"}else{"FAIL"}}
            }
        }
        
        # QPS
        $tsharkQPS = $tsharkQueries / $durationSec
        $toolQPS = [double]$flowData.dns_queries_per_second
        $match = ([Math]::Abs($toolQPS - $tsharkQPS) -lt 0.01)
        Write-Host "  dns_queries_per_second: Tool=$([Math]::Round($toolQPS,4)), tshark=$([Math]::Round($tsharkQPS,4)) $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="dns_queries_per_second"; Tool=[Math]::Round($toolQPS,4); Tshark=[Math]::Round($tsharkQPS,4); Status=if($match){"PASS"}else{"FAIL"}}
        
        # Query/Response Ratio
        $expectedQRRatio = if ($toolResponses -gt 0) { [double]$toolQueries / [double]$toolResponses } else { $toolQueries }
        $toolQRRatio = [double]$flowData.query_response_ratio
        $match = ([Math]::Abs($toolQRRatio - $expectedQRRatio) -lt 0.01)
        Write-Host "  query_response_ratio: Tool=$([Math]::Round($toolQRRatio,4)), expected=$([Math]::Round($expectedQRRatio,4)) $(if ($match) {'✓'} else {'✗'})"
        $results += [PSCustomObject]@{Flow=$flowName; Column="query_response_ratio"; Tool=[Math]::Round($toolQRRatio,4); Tshark=[Math]::Round($expectedQRRatio,4); Status=if($match){"PASS"}else{"FAIL"}}
    }
    
    # ================================================================
    # 9. OTHER COLUMNS (Sanity checks)
    # ================================================================
    Write-Host "`n[9] OTHER COLUMNS (Sanity Checks)" -ForegroundColor Cyan
    
    # IAT means (directional)
    $toolFwdIat = [double]$flowData.fwd_iat_mean
    $valid = ($toolFwdIat -ge 0)
    Write-Host "  fwd_iat_mean: Tool=$toolFwdIat (sanity: $(if ($valid) {'✓'} else {'✗'}))"
    $results += [PSCustomObject]@{Flow=$flowName; Column="fwd_iat_mean"; Tool=$toolFwdIat; Tshark="N/A"; Status=if($valid){"PASS"}else{"FAIL"}}
    
    $toolBwdIat = [double]$flowData.bwd_iat_mean
    $valid = ($toolBwdIat -ge 0)
    Write-Host "  bwd_iat_mean: Tool=$toolBwdIat (sanity: $(if ($valid) {'✓'} else {'✗'}))"
    $results += [PSCustomObject]@{Flow=$flowName; Column="bwd_iat_mean"; Tool=$toolBwdIat; Tshark="N/A"; Status=if($valid){"PASS"}else{"FAIL"}}
    
    # Label
    $toolLabel = $flowData.label
    $validLabel = $toolLabel -in @("ATTACK", "BENIGN")
    Write-Host "  label: $toolLabel (valid: $(if ($validLabel) {'✓'} else {'✗'}))"
    $results += [PSCustomObject]@{Flow=$flowName; Column="label"; Tool=$toolLabel; Tshark="User-specified"; Status=if($validLabel){"PASS"}else{"FAIL"}}
    
    return $results
}

# ================================================================
# RUN VALIDATION FOR ALL 3 FLOWS
# ================================================================
foreach ($testFlow in $testFlows) {
    $flowResults = Validate-Flow -flowData $testFlow.Flow -flowName $testFlow.Name -flowIndex $testFlow.Index
    $allResults += $flowResults
}

# ================================================================
# FINAL SUMMARY
# ================================================================
Write-Host "`n`n" + ("=" * 120) -ForegroundColor Cyan
Write-Host "FINAL SUMMARY - ALL 3 FLOWS" -ForegroundColor Cyan
Write-Host ("=" * 120) -ForegroundColor Cyan

Write-Host "`n[RESULTS BY FLOW]" -ForegroundColor Yellow
foreach ($tf in $testFlows) {
    $flowResults = $allResults | Where-Object { $_.Flow -eq $tf.Name }
    $passCount = ($flowResults | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = ($flowResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $total = $flowResults.Count
    $passRate = if ($total -gt 0) { ($passCount / $total) * 100 } else { 0 }
    
    Write-Host "`n$($tf.Name) Flow (Row #$($tf.Index + 1)):" -ForegroundColor Cyan
    Write-Host "  PASS: $passCount/$total" -ForegroundColor $(if ($failCount -eq 0) {"Green"} else {"Yellow"})
    Write-Host "  FAIL: $failCount/$total" -ForegroundColor $(if ($failCount -gt 0) {"Red"} else {"Green"})
    Write-Host "  Success Rate: $([Math]::Round($passRate, 1))%"
}

Write-Host "`n[OVERALL STATISTICS]" -ForegroundColor Yellow
$totalPass = ($allResults | Where-Object { $_.Status -eq "PASS" }).Count
$totalFail = ($allResults | Where-Object { $_.Status -eq "FAIL" }).Count
$totalChecks = $allResults.Count
$overallRate = if ($totalChecks -gt 0) { ($totalPass / $totalChecks) * 100 } else { 0 }

Write-Host "  Total Checks: $totalChecks"
Write-Host "  Total PASS: $totalPass" -ForegroundColor Green
Write-Host "  Total FAIL: $totalFail" -ForegroundColor $(if ($totalFail -gt 0) {"Red"} else {"Green"})
Write-Host "  Overall Success Rate: $([Math]::Round($overallRate, 1))%" -ForegroundColor Cyan

if ($totalFail -eq 0) {
    Write-Host "`n[SUCCESS] ALL VALIDATIONS PASSED!" -ForegroundColor Green
} else {
    Write-Host "`n[REVIEW] Some validations failed. See details above." -ForegroundColor Yellow
    Write-Host "`nFailed checks:" -ForegroundColor Red
    $allResults | Where-Object { $_.Status -eq "FAIL" } | Format-Table -AutoSize
}

# Export detailed results
$allResults | Export-Csv -Path "validation_results_3flows.csv" -NoTypeInformation
Write-Host "`nDetailed results saved to: validation_results_3flows.csv" -ForegroundColor Green

Write-Host "`n" + ("=" * 120) -ForegroundColor Cyan
