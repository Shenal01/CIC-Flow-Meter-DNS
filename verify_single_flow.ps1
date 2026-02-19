# Manual Flow Verification Script
# Validates individual flows from CSV against PCAP using tshark

param(
    [Parameter(Mandatory=$true)]
    [string]$PcapFile,
    
    [Parameter(Mandatory=$true)]
    [string]$SrcIP,
    
    [Parameter(Mandatory=$true)]
    [int]$SrcPort,
    
    [Parameter(Mandatory=$true)]
    [string]$DstIP,
    
    [Parameter(Mandatory=$true)]
    [int]$DstPort,
    
    [Parameter(Mandatory=$true)]
    [string]$Protocol
)

Write-Host "="*80
Write-Host "MANUAL FLOW VERIFICATION"
Write-Host "="*80
Write-Host "Flow: $SrcIP`:$SrcPort -> $DstIP`:$DstPort ($Protocol)"
Write-Host ""

# Build tshark filter for this specific flow
$filter = "ip.src == $SrcIP and ip.dst == $DstIP and udp.srcport == $SrcPort and udp.dstport == $DstPort"

# Count total packets in this flow
Write-Host "[1] Total Packets in Flow:"
$totalPackets = (tshark -r $PcapFile -Y $filter 2>$null | Measure-Object -Line).Lines
Write-Host "    $totalPackets packets"

# Count DNS queries in this flow
Write-Host "`n[2] DNS Queries:"
$queries = (tshark -r $PcapFile -Y "$filter and dns.flags.response == 0" 2>$null | Measure-Object -Line).Lines
Write-Host "    $queries queries"

# Count DNS responses in this flow
Write-Host "`n[3] DNS Responses:"
$responses = (tshark -r $PcapFile -Y "$filter and dns.flags.response == 1" 2>$null | Measure-Object -Line).Lines
Write-Host "    $responses responses"

# Get packet details
Write-Host "`n[4] Packet Details:"
tshark -r $PcapFile -Y $filter -T fields -e frame.number -e frame.time -e frame.len -e dns.flags.response -e dns.qry.name -e dns.qry.type 2>$null | ForEach-Object {
    Write-Host "    $_"
}

# Calculate amplification factor
Write-Host "`n[5] Byte Analysis:"
$queryBytes = (tshark -r $PcapFile -Y "$filter and dns.flags.response == 0" -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum
$responseBytes = (tshark -r $PcapFile -Y "$filter and dns.flags.response == 1" -T fields -e frame.len 2>$null | Measure-Object -Sum).Sum

Write-Host "    Query bytes: $queryBytes"
Write-Host "    Response bytes: $responseBytes"

if ($queryBytes -gt 0) {
    $ampFactor = [decimal]($responseBytes / $queryBytes)
    Write-Host "    Amplification factor: $($ampFactor.ToString('F4'))"
} else {
    Write-Host "    Amplification factor: 0.0000 (no queries)"
}

# Calculate query/response ratio
if ($responses -gt 0) {
    $qrRatio = [decimal]($queries / $responses)
    Write-Host "    Query/Response ratio: $($qrRatio.ToString('F4'))"
} else {
    Write-Host "    Query/Response ratio: $queries.0000 (no responses)"
}

# Check query types
Write-Host "`n[6] Query Type Analysis:"
$anyQueries = (tshark -r $PcapFile -Y "$filter and dns.qry.type == 255" 2>$null | Measure-Object -Line).Lines
$txtQueries = (tshark -r $PcapFile -Y "$filter and dns.qry.type == 16" 2>$null | Measure-Object -Line).Lines
$aQueries = (tshark -r $PcapFile -Y "$filter and dns.qry.type == 1" 2>$null | Measure-Object -Line).Lines

Write-Host "    ANY queries (type 255): $anyQueries"
Write-Host "    TXT queries (type 16): $txtQueries"
Write-Host "    A queries (type 1): $aQueries"

if ($queries -gt 0) {
    $anyRatio = [decimal]($anyQueries / $queries)
    $txtRatio = [decimal]($txtQueries / $queries)
    Write-Host "    ANY query ratio: $($anyRatio.ToString('F4'))"
    Write-Host "    TXT query ratio: $($txtRatio.ToString('F4'))"
}

# Get timing
Write-Host "`n[7] Timing Analysis:"
$timestamps = tshark -r $PcapFile -Y $filter -T fields -e frame.time_epoch 2>$null
if ($timestamps -and $timestamps.Count -gt 0) {
    $firstTime = [double]$timestamps[0]
    $lastTime = [double]$timestamps[-1]
    $durationSec = $lastTime - $firstTime
    $durationMs = $durationSec * 1000
    
    Write-Host "    First packet: $firstTime"
    Write-Host "    Last packet: $lastTime"
    Write-Host "    Duration: $($durationMs.ToString('F4')) ms"
    
    if ($durationSec -gt 0) {
        $qps = [decimal]($queries / $durationSec)
        Write-Host "    Queries per second: $($qps.ToString('F4'))"
    }
} else {
    Write-Host "    (Single packet flow - no duration)"
}

# Get packet sizes
Write-Host "`n[8] Packet Size Analysis:"
$allSizes = tshark -r $PcapFile -Y $filter -T fields -e frame.len 2>$null | ForEach-Object { [int]$_ }
if ($allSizes) {
    $avgSize = ($allSizes | Measure-Object -Average).Average
    $minSize = ($allSizes | Measure-Object -Minimum).Minimum
    $maxSize = ($allSizes | Measure-Object -Maximum).Maximum
    
    Write-Host "    Average: $($avgSize.ToString('F2')) bytes"
    Write-Host "    Min: $minSize bytes"
    Write-Host "    Max: $maxSize bytes"
}

Write-Host "`n" + ("="*80)
Write-Host "VERIFICATION COMPLETE"
Write-Host ("="*80)
