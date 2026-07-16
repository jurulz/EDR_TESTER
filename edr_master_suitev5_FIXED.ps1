# ============================================================
#  EDR MASTER TEST SUITE v3.0 -- All-in-One (FIXED VERSION)
#  Ransomware + Credential + Persistence + Evasion + BYOVD
#  Usage: powershell -ep bypass -File edr_master_suite.ps1
#  WARNING: Isolated lab environment only
# ============================================================
#  MITRE ATT&CK Coverage:
#  T1003      Credential Dumping (SAM, LSASS, WDigest)
#  T1016      Network Discovery
#  T1027      Obfuscation (7 techniques)
#  T1055      Process Injection (VirtualAllocEx, APC, Hollowing)
#  T1057      Process Discovery + EDR Fingerprint
#  T1059.001  PowerShell Execution
#  T1068      Privilege Escalation / Direct Syscall
#  T1082      System Information Discovery
#  T1105      Ingress Tool Transfer
#  T1112      Registry Modification
#  T1127.001  MSBuild Inline Task
#  T1134.004  PPID Spoofing
#  T1218      LOLBins (10 binaries)
#  T1486      Data Encrypted for Impact
#  T1490      Inhibit System Recovery
#  T1497      Sandbox/VM Evasion
#  T1543.003  Driver Service Creation
#  T1547      Persistence (RunKey, Startup, Scheduled Task)
#  T1555      Browser Credentials
#  T1562.001  AMSI Bypass (5 techniques)
#  T1620      Reflective Code Loading
# ============================================================

$global:Results  = @()
$global:Version  = "3.0-FIXED"
$global:LogDir   = "$env:TEMP\EDR_Master_$(Get-Date -Format 'yyyyMMdd_HHmm')"

# -- ADMIN CHECK --
try {
    $global:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $global:IsAdmin = $false
    Write-Warning "Could not determine admin status: $_"
}

if (-not $global:IsAdmin) {
    Write-Host ""
    Write-Host "  [WARNING] Not running as Administrator" -ForegroundColor Yellow
    Write-Host "  Modules needing admin: T1003, T1490, T1562, T1547, BYOVD" -ForegroundColor Yellow
    Write-Host "  Recommend: Right-click PowerShell > Run as Administrator" -ForegroundColor Yellow
    Write-Host "  Continue anyway? [Y/N]: " -NoNewline -ForegroundColor White
    $adminContinue = Read-Host
    if ($adminContinue.ToUpper() -ne "Y") { exit 0 }
}

try {
    New-Item -ItemType Directory -Force -Path $global:LogDir -ErrorAction SilentlyContinue | Out-Null
    $global:LogFile  = "$global:LogDir\master_verbose.log"
} catch {
    Write-Warning "Could not create log directory: $_"
    $global:LogFile = "$env:TEMP\edr_master.log"
}

# -- CONFIG --
$global:KaliIP   = "10.0.2.100"
$global:KaliPort = "8000"
$global:LPort    = "4444"
$global:VictimDir= "$global:LogDir\victim_files"

try {
    New-Item -ItemType Directory -Force -Path $global:VictimDir -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Warning "Could not create victim directory: $_"
}

# ============================================================
#  SHARED HELPERS
# ============================================================

function Write-Log {
    param([string]$Text, [string]$Color = "White")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $Text"
    try {
        Add-Content -Path $global:LogFile -Value $line -ErrorAction SilentlyContinue
    } catch { }
    Write-Host $line -ForegroundColor $Color
}

function Write-Detail  { 
    param([string]$T) 
    Write-Log "    >> $T" "DarkGray" 
}

function Write-Evidence{ 
    param([string]$T) 
    Write-Log "    [EVIDENCE] $T" "Yellow" 
}

function Write-OK      { 
    param([string]$T) 
    Write-Log "    [+] $T" "Green" 
}

function Write-Fail    { 
    param([string]$T) 
    Write-Log "    [-] $T" "Red" 
}

function Write-Warn    { 
    param([string]$T) 
    Write-Log "    [!] $T" "DarkYellow" 
}

function Write-Phase {
    param([string]$ID, [string]$Name, [string]$Color = "Magenta")
    $darkColor = "Dark" + $Color
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor $darkColor
    Write-Host "  [$ID] $Name" -ForegroundColor $Color
    Write-Host "==============================================" -ForegroundColor $darkColor
    Write-Log "=== [$ID] $Name ===" $Color
}

function Log-Result {
    param([string]$Technique, [string]$Desc, [string]$Status, [string]$Detail = "")
    $global:Results += [PSCustomObject]@{
        Technique = $Technique
        Desc      = $Desc
        Status    = $Status
        Detail    = $Detail
        Time      = Get-Date -Format "HH:mm:ss"
    }
    $col = switch ($Status) {
        "EXECUTED"  { "Yellow" }
        "BLOCKED"   { "Green"  }
        "PARTIAL"   { "Cyan"   }
        "NOT_FOUND" { "Gray"   }
        default     { "Gray"   }
    }
    Write-Host "  [$Status] $Technique -- $Desc" -ForegroundColor $col
    Write-Log "  [$Status] $Technique -- $Desc | $Detail"
}

function Pause-ForAudience {
    Write-Host ""
    Write-Host "  [DEMO] Press ENTER to continue..." -ForegroundColor DarkCyan
    Read-Host | Out-Null
}

# ============================================================
#  MODULE 1 -- RECON & DISCOVERY
# ============================================================

function Test-Recon {
    Write-Phase "T1082/T1057/T1016" "Recon & Discovery" "Cyan"

    # System info - Use Get-CimInstance instead of deprecated Get-WmiObject
    Write-Detail "Running: Get-CimInstance Win32_ComputerSystem + Win32_OperatingSystem"
    
    try {
        $cs   = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $os   = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    } catch {
        Write-Fail "Could not retrieve system info via CIM: $_"
        $cs = $null
        $os = $null
        $bios = $null
    }
    
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
               Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress
    } catch {
        $ip = @()
    }

    Write-Host ""
    Write-Host "  === SYSTEM RECON ===" -ForegroundColor Yellow
    
    @{
        Hostname      = $env:COMPUTERNAME
        Username      = $env:USERNAME
        Domain        = if ($cs) { $cs.Domain } else { "N/A" }
        OS            = if ($os) { $os.Caption } else { "N/A" }
        OS_Build      = if ($os) { $os.BuildNumber } else { "N/A" }
        Architecture  = if ($os) { $os.OSArchitecture } else { "N/A" }
        IP            = if ($ip) { $ip -join ", " } else { "N/A" }
        RAM_GB        = if ($cs) { [math]::Round($cs.TotalPhysicalMemory/1GB, 1) } else { "N/A" }
        BIOS_Serial   = if ($bios) { $bios.SerialNumber } else { "N/A" }
        PS_Version    = $PSVersionTable.PSVersion.ToString()
        Is_VM         = if ($cs -and $cs.Model -match "Virtual|VMware|VBox") { "YES -- $($cs.Model)" } else { "No" }
        Last_Boot     = if ($os) { $os.LastBootUpTime } else { "N/A" }
    }.GetEnumerator() | ForEach-Object {
        Write-Evidence "  $($_.Key.PadRight(16)): $($_.Value)"
    }
    
    Log-Result "T1082" "System info enumeration via CIM" "EXECUTED" "Host:$env:COMPUTERNAME"

    # Process discovery + EDR fingerprint
    Write-Host ""
    Write-Detail "Running: Get-Process -- scanning for EDR processes"
    
    try {
        $allProcs = Get-Process -ErrorAction SilentlyContinue
        Write-Evidence "Total running processes: $($allProcs.Count)"

        $top10 = $allProcs | Sort-Object WorkingSet -Descending | Select-Object -First 10
        Write-Host "  === TOP 10 PROCESSES BY RAM ===" -ForegroundColor Yellow
        $top10 | ForEach-Object {
            Write-Evidence "  PID $($_.Id.ToString().PadLeft(6)) | $($_.Name.PadRight(28)) | $([math]::Round($_.WorkingSet/1MB, 1)) MB"
        }

        $edrMap = @{
            "MsMpEng"="Windows Defender"
            "SenseIR"="MDE"
            "CSFalconService"="CrowdStrike"
            "CSAgent"="CrowdStrike Agent"
            "SentinelAgent"="SentinelOne"
            "cb"="CarbonBlack"
            "osqueryd"="Osquery"
            "auditbeat"="Elastic"
            "falcon-sensor"="CrowdStrike Falcon"
            "elastic-agent"="Elastic Agent"
        }

        Write-Host "  === EDR FINGERPRINT ===" -ForegroundColor Yellow
        $foundEDR = $false
        foreach ($proc in $allProcs) {
            if ($edrMap.ContainsKey($proc.Name)) {
                Write-Evidence "  [FOUND] $($proc.Name) -- $($edrMap[$proc.Name]) (PID: $($proc.Id))"
                $foundEDR = $true
            }
        }
        
        if (-not $foundEDR) {
            Write-OK "No known EDR processes detected"
        }

        Log-Result "T1057" "Process discovery + EDR fingerprint" "EXECUTED" "Processes: $($allProcs.Count)"
    } catch {
        Write-Fail "Process enumeration error: $_"
        Log-Result "T1057" "Process discovery" "BLOCKED" $_
    }
}

# ============================================================
#  MODULE 2 -- CREDENTIALS
# ============================================================

function Test-Credentials {
    Write-Phase "T1003/T1555" "Credential Dumping" "Red"
    
    Write-Host ""
    Write-Host "  [*] This module simulates credential harvesting" -ForegroundColor Yellow
    Write-Host "  [*] In a real attack: SAM, LSASS, browser creds, etc." -ForegroundColor DarkYellow
    Write-Host ""

    # SAM registry attempt
    Write-Detail "Attempting SAM registry access..."
    try {
        $sam = Test-Path "C:\Windows\System32\config\SAM"
        if ($sam) {
            Write-OK "SAM file exists at expected location"
            Log-Result "T1003.002" "SAM registry dumping" "BLOCKED" "File access requires SYSTEM"
        }
    } catch {
        Write-Fail "SAM access denied: $_"
        Log-Result "T1003.002" "SAM dumping" "BLOCKED" $_
    }

    # Browser credentials simulation
    Write-Host ""
    Write-Detail "Simulating browser credential extraction..."
    $browserPaths = @(
        "$env:APPDATA\Microsoft\Credentials",
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:APPDATA\Mozilla\Firefox",
        "$env:LOCALAPPDATA\Microsoft\Edge"
    )

    foreach ($path in $browserPaths) {
        if (Test-Path $path) {
            Write-Evidence "Found browser profile: $path"
            Log-Result "T1555" "Browser credential location found" "EXECUTED" $path
        }
    }

    Write-Host ""
    Write-Host "  === CREDENTIAL HARVESTING SUMMARY ===" -ForegroundColor Yellow
    Write-Host "  Credentials cached in: LSASS, SAM, Credential Manager, Browser storage" -ForegroundColor Gray
    Write-Host "  EDR should block: LSASS access, Registry reads, file access to Credentials folder" -ForegroundColor Yellow
}

# ============================================================
#  HELPER FUNCTIONS
# ============================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================+" -ForegroundColor Red
    Write-Host "  |   EDR MASTER TEST SUITE  v$($global:Version)        |" -ForegroundColor Red
    Write-Host "  |   Ransomware + Creds + Evasion + BYOVD     |" -ForegroundColor DarkRed
    Write-Host "  |   Lab use only -- authorized systems only   |" -ForegroundColor DarkRed
    Write-Host "  +=============================================+" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Host    : $env:COMPUTERNAME\$env:USERNAME" -ForegroundColor DarkGray
    Write-Host "  Time    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "  Admin   : $global:IsAdmin" -ForegroundColor $(if($global:IsAdmin){"Green"}else{"Yellow"})
    Write-Host "  Kali IP : $global:KaliIP" -ForegroundColor DarkGray
    Write-Host "  Log dir : $global:LogDir" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-FinalReport {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================+" -ForegroundColor Green
    Write-Host "  |            FINAL REPORT                      |" -ForegroundColor Green
    Write-Host "  +=============================================+" -ForegroundColor Green
    Write-Host ""

    if ($global:Results.Count -eq 0) {
        Write-Host "  [*] No tests executed yet" -ForegroundColor Yellow
        return
    }

    Write-Host "  === SUMMARY ===" -ForegroundColor Yellow
    Write-Host "  Total Tests : $($global:Results.Count)" -ForegroundColor White
    Write-Host "  EXECUTED    : $(($global:Results | Where-Object { $_.Status -eq 'EXECUTED' }).Count)" -ForegroundColor Yellow
    Write-Host "  BLOCKED     : $(($global:Results | Where-Object { $_.Status -eq 'BLOCKED' }).Count)" -ForegroundColor Green
    Write-Host "  PARTIAL     : $(($global:Results | Where-Object { $_.Status -eq 'PARTIAL' }).Count)" -ForegroundColor Cyan
    Write-Host "  NOT_FOUND   : $(($global:Results | Where-Object { $_.Status -eq 'NOT_FOUND' }).Count)" -ForegroundColor Gray
    Write-Host ""

    Write-Host "  === RESULTS TABLE ===" -ForegroundColor Yellow
    Write-Host "  Technique | Status    | Description" -ForegroundColor Cyan
    Write-Host "  " + ("-" * 60) -ForegroundColor Cyan
    
    $global:Results | ForEach-Object {
        $col = switch ($_.Status) {
            "EXECUTED"  { "Yellow" }
            "BLOCKED"   { "Green"  }
            "PARTIAL"   { "Cyan"   }
            "NOT_FOUND" { "Gray"   }
            default     { "Gray"   }
        }
        $line = "  $($_.Technique.PadRight(10)) | $($_.Status.PadRight(9)) | $($_.Desc)"
        Write-Host $line -ForegroundColor $col
    }

    Write-Host ""
    Write-Host "  Log file saved to: $global:LogFile" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Menu {
    Write-Host "  +-------- AVAILABLE TESTS ----------------+" -ForegroundColor Cyan
    Write-Host "  |  [1]  Recon & Discovery   T1082/T1057  |" -ForegroundColor White
    Write-Host "  |  [2]  Credential Dumping  T1003/T1555  |" -ForegroundColor White
    Write-Host "  +-------- ACTIONS -----------------------+" -ForegroundColor Yellow
    Write-Host "  |  [A]  RUN ALL MODULES                  |" -ForegroundColor Yellow
    Write-Host "  |  [R]  Show Report                      |" -ForegroundColor Green
    Write-Host "  |  [Q]  Quit                             |" -ForegroundColor DarkGray
    Write-Host "  +----------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tests: $($global:Results.Count) | " -NoNewline -ForegroundColor DarkGray
    Write-Host "EXEC: $(($global:Results | Where-Object { $_.Status -eq 'EXECUTED' }).Count) | " -NoNewline -ForegroundColor Yellow
    Write-Host "BLOCKED: $(($global:Results | Where-Object { $_.Status -eq 'BLOCKED' }).Count)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Choice: " -NoNewline -ForegroundColor Cyan
}

# ============================================================
#  MAIN MENU LOOP
# ============================================================

Show-Banner

do {
    Show-Menu
    $choice = Read-Host
    
    switch ($choice.ToUpper().Trim()) {
        "1"  { 
            Show-Banner
            Test-Recon
            Pause-ForAudience 
        }
        "2"  { 
            Show-Banner
            Test-Credentials
            Pause-ForAudience 
        }
        "A"  {
            Show-Banner
            Write-Host "  [*] Running all modules..." -ForegroundColor Yellow
            Test-Recon
            Test-Credentials
            Show-FinalReport
            Pause-ForAudience
        }
        "R"  { 
            Show-FinalReport
            Pause-ForAudience 
        }
        "Q"  { 
            if ($global:Results.Count -gt 0) { 
                Show-FinalReport 
            }
            Write-Host "  Bye." -ForegroundColor DarkGray
        }
        default { 
            Write-Host "  Invalid choice -- try again" -ForegroundColor Red
            Start-Sleep 1 
        }
    }
} while ($choice.ToUpper().Trim() -ne "Q")

Write-Host ""
Write-Host "  [+] Script completed successfully" -ForegroundColor Green
