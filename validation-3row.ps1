# =========================
# CONFIG
# =========================
$pcap     = "C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\DDoS-TCP_Flood.pcap"
$csvPath  = "C:\Users\shenal\Downloads\reseraach\CIC_IOT_2023\PCAP\New-CIC-JAVA\DDoS_TCP_Flood_fixed.csv"


# =========================
# LOAD CSV
# =========================
$csv = Import-Csv $csvPath

if (!$csv) {
    throw "CSV could not be loaded - check the path."
}

Write-Host "`nLoaded $($csv.Count) rows from CSV." -ForegroundColor Green



# =========================
# FUNCTION — VERIFY ONE FLOW
# =========================
function Validate-Flow {
    param($flow)

    $srcIp   = $flow.src_ip
    $dstIp   = $flow.dst_ip
    $srcPort = $flow.src_port
    $dstPort = $flow.dst_port

    Write-Host "`n=== SELECTED FLOW ===" -ForegroundColor Yellow
    $flow | Format-List

    $filterFwd  = "ip.src == $srcIp and ip.dst == $dstIp and udp.srcport == $srcPort and udp.dstport == $dstPort"
    $filterBwd  = "ip.src == $dstIp and ip.dst == $srcIp and udp.srcport == $dstPort and udp.dstport == $srcPort"
    $filterBoth = "($filterFwd) or ($filterBwd)"

    Write-Host "`n--- tshark verification running ---" -ForegroundColor Magenta


    # ------------------------
    # PACKET COUNTS
    # ------------------------
    $fwdPkts = (tshark -r $pcap -Y "$filterFwd" -T fields -e frame.number).Count
    $bwdPkts = (tshark -r $pcap -Y "$filterBwd" -T fields -e frame.number).Count
    $totPkts = $fwdPkts + $bwdPkts

    Write-Host "`nPacket counts:"
    "{0,-22} {1}" -f "Forward:", $fwdPkts
    "{0,-22} {1}" -f "Backward:", $bwdPkts
    "{0,-22} {1}" -f "Total:", $totPkts

    if ($totPkts -eq [int]$flow.total_packets) {
        Write-Host "PASS: total packet count matches CSV" -ForegroundColor Green
    } else {
        Write-Host "FAIL: total packet count mismatch (CSV=$($flow.total_packets), PCAP=$totPkts)" -ForegroundColor Red
    }


    # ------------------------
    # DURATION
    # ------------------------
    $times = tshark -r $pcap -Y "$filterBoth" -T fields -e frame.time_epoch |
             ForEach-Object {[double]$_} |
             Sort-Object

    if ($times.Count -gt 1) {
        $duration = [math]::Round(($times[-1] - $times[0]), 6)
    } else {
        $duration = 0
    }

    Write-Host "`nDuration:"
    "{0,-22} {1}" -f "Calculated:", $duration
    "{0,-22} {1}" -f "CSV:", $flow.duration

    if ([math]::Abs($duration - [double]$flow.duration) -lt 0.001) {
        Write-Host "PASS: duration matches" -ForegroundColor Green
    } else {
        Write-Host "FAIL: duration mismatch" -ForegroundColor Red
    }


    # ------------------------
    # DNS STATS
    # ------------------------
    $dnsFilter = "$filterBoth and dns"
    $dnsQueries   = (tshark -r $pcap -Y "$dnsFilter and dns.flags.response == 0" -T fields -e frame.number).Count
    $dnsResponses = (tshark -r $pcap -Y "$dnsFilter and dns.flags.response == 1" -T fields -e frame.number).Count

    Write-Host "`nDNS traffic:"
    "{0,-22} {1}" -f "Queries:", $dnsQueries
    "{0,-22} {1}" -f "Responses:", $dnsResponses

    if ($dnsQueries -eq [int]$flow.dns_total_queries) {
        Write-Host "PASS: DNS query count matches" -ForegroundColor Green
    } else {
        Write-Host "FAIL: DNS query count mismatch" -ForegroundColor Red
    }

    if ($dnsResponses -eq [int]$flow.dns_total_responses) {
        Write-Host "PASS: DNS response count matches" -ForegroundColor Green
    } else {
        Write-Host "FAIL: DNS response count mismatch" -ForegroundColor Red
    }


    # ------------------------
    # BYTES (forward/backward)
    # ------------------------
    $fwdBytes = (tshark -r $pcap -Y "$filterFwd" -T fields -e frame.len |
                 ForEach-Object {[int]$_} |
                 Measure-Object -Sum).Sum

    $bwdBytes = (tshark -r $pcap -Y "$filterBwd" -T fields -e frame.len |
                 ForEach-Object {[int]$_} |
                 Measure-Object -Sum).Sum

    $totalBytes = $fwdBytes + $bwdBytes

    Write-Host "`nBytes:"
    "{0,-22} {1}" -f "Forward:", $fwdBytes
    "{0,-22} {1}" -f "Backward:", $bwdBytes
    "{0,-22} {1}" -f "Total:", $totalBytes

    if ($totalBytes -eq [int]$flow.total_bytes) {
        Write-Host "PASS: total bytes match" -ForegroundColor Green
    } else {
        Write-Host "FAIL: total bytes mismatch" -ForegroundColor Red
    }

    Write-Host "`n=== VALIDATION COMPLETE ===`n" -ForegroundColor Cyan
}



# =========================
# PICK DNS-RICH FLOWS
# =========================
$dnsFlows = $csv | Where-Object {
    [int]$_.dns_total_queries -gt 5 -and
    [int]$_.dns_total_responses -gt 5
}

if ($dnsFlows.Count -lt 3) {
    throw "Not enough DNS-rich flows to test 3 rows."
}

$top    = $dnsFlows[0]
$middle = $dnsFlows[ [int]($dnsFlows.Count / 2) ]
$bottom = $dnsFlows[-1]

$testFlows = @($top, $middle, $bottom)

Write-Host "`nWe will validate: TOP / MIDDLE / BOTTOM flows`n" -ForegroundColor Cyan



# =========================
# RUN VALIDATION
# =========================
$i = 1
foreach ($f in $testFlows) {

    Write-Host "`n###########################" -ForegroundColor DarkCyan
    Write-Host "### VALIDATING FLOW $i" -ForegroundColor DarkCyan
    Write-Host "###########################" -ForegroundColor DarkCyan

    Validate-Flow -flow $f
    $i++
}
