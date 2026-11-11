
# ========================================================
# SOC Tier 1 Incident Investigation
# Organization: Bayline Logistics (Fictional)
# Dataset: Synthetic security events
# Analyst: SOC Tier 1
# ========================================================

# 1. IMPORT CSV DATA

$csvPath = Join-Path $PSScriptRoot "..\data\practice-events.csv"

if (-not (Test-Path $csvPath)) {
    throw "Dataset not found: $csvPath"
}

$practice = @(Import-Csv -Path $csvPath)

Write-Host "`n=== DATASET VALIDATION ==="
Write-Host "Total records: $($practice.Count)"

if ($practice.Count -ne 12) {
    Write-Warning "Expected 12 records."
}

# 2. FULL EVENT TIMELINE

Write-Host "`n=== COMPLETE EVENT TIMELINE ==="

$practice |
    Sort-Object timestamp |
    Format-Table record_id,timestamp,user,host,source,action -AutoSize

# 3. DANA'S EVENT TIMELINE

Write-Host "`n=== DANA: FIN-09 ==="

$danaEvents = @(
    $practice | Where-Object {
        $_.user -eq 'dana'
    } | Sort-Object timestamp
)

$danaEvents |
    Format-Table record_id,timestamp,source,action,detail -Wrap

# 4. LEO'S AUTHENTICATION TIMELINE

Write-Host "`n=== LEO: AUTHENTICATION EVENTS ==="

$leoEvents = @(
    $practice | Where-Object {
        $_.user -eq 'leo'
    } | Sort-Object timestamp
)

$leoEvents |
    Format-Table record_id,timestamp,event_id,host,src_ip,action -AutoSize

# 5. FAILED AUTHENTICATION ANALYSIS

Write-Host "`n=== FAILED LOGON ANALYSIS: EVENT 4625 ==="

$failedLogons = @(
    $practice | Where-Object {
        $_.event_id -eq '4625'
    }
)

$failedLogons |
    Group-Object user,host,src_ip |
    Select-Object Count,Name |
    Format-Table -AutoSize

Write-Host "Total failures: $($failedLogons.Count)"

# 6. SUCCESSFUL AUTHENTICATION ANALYSIS

Write-Host "`n=== SUCCESSFUL LOGONS: EVENT 4624 ==="

$practice |
    Where-Object {
        $_.event_id -eq '4624'
    } |
    Format-Table record_id,timestamp,user,host,src_ip,detail -Wrap

# 7. EMAIL EVENT ANALYSIS

Write-Host "`n=== EMAIL DELIVERY ==="

$practice |
    Where-Object {
        $_.source -eq 'email'
    } |
    Format-List record_id,timestamp,user,action,detail

# 8. POWERSHELL EXECUTION ANALYSIS

Write-Host "`n=== POWERSHELL ACTIVITY ==="

$practice |
    Where-Object {
        $_.detail -match 'powershell.exe|Get-ComputerInfo|PowerShell from user-writable'
    } |
    Sort-Object timestamp |
    Format-List record_id,timestamp,user,host,source,action,detail

# 9. SCRIPT BLOCK LOGGING

Write-Host "`n=== POWERSHELL EVENT 4104 ==="

$practice |
    Where-Object {
        $_.event_id -eq '4104'
    } |
    Format-List record_id,timestamp,user,host,detail

# 10. CORRELATE DANA'S PROCESS ID

Write-Host "`n=== PROCESS CORRELATION: PID 6220 ==="

$practice |
    Where-Object {
        $_.detail -match '(?<!\d)6220(?!\d)'
    } |
    Sort-Object timestamp |
    Format-Table record_id,timestamp,source,action,detail -Wrap

# 11. OUTBOUND NETWORK CONNECTIONS

Write-Host "`n=== PROXY / NETWORK ACTIVITY ==="

$practice |
    Where-Object {
        $_.source -eq 'proxy'
    } |
    Format-List record_id,timestamp,user,host,src_ip,action,detail

# 12. APPROVED ADMINISTRATION COMPARISON

Write-Host "`n=== SVC_OPS / APPROVED ACTIVITY ==="

$practice |
    Where-Object {
        $_.user -eq 'svc_ops'
    } |
    Sort-Object timestamp |
    Format-List record_id,timestamp,host,src_ip,action,detail

# 13. CORRELATE EMAIL MESSAGE M202

Write-Host "`n=== EMAIL CORRELATION: MESSAGE M202 ==="

$practice |
    Where-Object {
        $_.detail -match 'M202'
    } |
    Format-List record_id,timestamp,source,user,action,detail

# 14. END OF INVESTIGATION

Write-Host "`n=== INVESTIGATION QUERIES COMPLETE ==="
Write-Host "Review output against the incident tickets."
Write-Host "No containment or remediation was performed."
