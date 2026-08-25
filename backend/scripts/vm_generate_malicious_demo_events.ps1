<#
.SYNOPSIS
  Generates real Sysmon telemetry that matches all 15 of NightOwl's detection
  rules, for use as a malicious-pattern EVTX fixture (Phase 4 E2E testing /
  Day 25 demo dataset). See docs/02_NightOwl_Handbook_Vol2_Roadmap.md and
  backend/tests/detection/test_rules_matrix.py.

.DESCRIPTION
  Every one of the 15 commands below reproduces the exact Image /
  CommandLine / TargetFilename / TargetObject / DestinationPort values that
  test_rules_matrix.py already proves fire each rule -- this isn't a guess,
  it's the same fixture data running for real so Sysmon logs it for real.

  This is NOT malware. Nothing here downloads or runs an actual payload,
  touches real credentials, or dumps real LSASS/SAM data:
    - the certutil/Invoke-WebRequest steps hit real but harmless URLs
    - the "LSASS dump" and "SAM dump" steps are look-alike command lines
      (echo'd text / an access-denied-safe reg.exe invocation), not real
      memory or hive access
    - the file/registry/scheduled-task artifacts this script creates are
      removed by this same script before it exits
    - the two "lateral movement" network rules connect to 127.0.0.1 only --
      nothing leaves the VM
    - the IFEO debugger hijack targets a made-up executable name that
      nothing on the system ever invokes, never a real system binary

.SAFETY
  Run this ONLY on the disposable/snapshot Sysmon-enabled VM already set up
  for the sysmon_vm_capture.evtx fixture -- never on your host machine.
  Run as Administrator (needed for the HKLM IFEO step).

.USAGE
  1. Run this script on the VM (elevated PowerShell). It prints a start/end
     UTC timestamp window.
  2. Export just that window:
       wevtutil epl Microsoft-Windows-Sysmon/Operational C:\path\sysmon_malicious_demo.evtx /q:"*[System[TimeCreated[@SystemTime>='<start>'] and TimeCreated[@SystemTime<='<end>']]]"
     (the script prints this command with the real timestamps filled in)
  3. Copy the resulting file into this repo as
     data/sample_logs/sysmon_malicious_demo.evtx
#>

$ErrorActionPreference = 'Continue'
$startTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host "=== NightOwl malicious-pattern event generation starting: $startTime ==="

function Invoke-LoopbackConnection {
    # Real TCP connect+accept on 127.0.0.1 so Sysmon logs a completed
    # NetworkConnect event with the given DestinationPort -- nothing leaves
    # the VM, and both ends of the connection are this same process.
    param([int]$Port)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    try {
        $acceptTask = $listener.AcceptTcpClientAsync()
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect('127.0.0.1', $Port)
        $acceptTask.Wait(2000) | Out-Null
        Start-Sleep -Milliseconds 300
        $client.Close()
    } finally {
        $listener.Stop()
    }
}

# 1. Suspicious Encoded PowerShell Command (T1059.001)
Write-Host "[1/15] encoded powershell"
powershell.exe -EncodedCommand aQBlAHgA 2>$null

# 2. Certutil Download via urlcache/split (T1105) -- real but harmless URL
Write-Host "[2/15] certutil urlcache/split"
$certOut = "$env:TEMP\nightowl_test_download.txt"
certutil.exe -urlcache -split -f "https://www.google.com/robots.txt" $certOut 2>$null | Out-Null
Remove-Item -Path $certOut -Force -ErrorAction SilentlyContinue

# 3. PowerShell Execution Policy Bypass (T1059.001)
Write-Host "[3/15] execution policy bypass"
powershell.exe -ExecutionPolicy Bypass -Command "Write-Output 'nightowl policy bypass test'" | Out-Null

# 4. Suspicious Network Connection from LOLBin (T1071.001) -- real outbound from powershell.exe
Write-Host "[4/15] lolbin network connection"
try { Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}

# 5. Suspicious Executable Written to Public or Temp Directory (T1105)
Write-Host "[5/15] suspicious file write"
$dropPath = "C:\Users\Public\nightowl_update_test.exe"
New-Item -Path $dropPath -ItemType File -Force | Out-Null
Remove-Item -Path $dropPath -Force -ErrorAction SilentlyContinue

# 6. Registry Run Key Persistence (T1547.001)
Write-Host "[6/15] registry run key"
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $runKey -Name 'NightOwlTest' -Value 'C:\Users\Public\nightowl_update_test.exe' -Force
Remove-ItemProperty -Path $runKey -Name 'NightOwlTest' -Force -ErrorAction SilentlyContinue

# 7. Registry IFEO Debugger Hijack (T1546.012) -- fake target name, nothing ever invokes it
Write-Host "[7/15] registry ifeo debugger hijack (safe fake target, requires admin)"
$ifeoKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\NightOwlTestTarget.exe'
New-Item -Path $ifeoKey -Force | Out-Null
Set-ItemProperty -Path $ifeoKey -Name 'Debugger' -Value 'C:\Windows\System32\cmd.exe' -Force
Remove-Item -Path $ifeoKey -Force -Recurse -ErrorAction SilentlyContinue

# 8. Scheduled Task Creation via schtasks.exe (T1053.005)
Write-Host "[8/15] schtasks /create"
schtasks.exe /create /tn "NightOwlTestTask" /tr "cmd.exe /c exit" /sc onlogon /f 2>$null | Out-Null
schtasks.exe /delete /tn "NightOwlTestTask" /f 2>$null | Out-Null

# 9. Suspicious Scheduled Task via PowerShell Cmdlet (T1053.005) -- builds the action object only, never registers a task
Write-Host "[9/15] New-ScheduledTaskAction (build only, not registered)"
powershell.exe -Command "New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit' | Out-Null"

# 10. Suspicious Mshta Execution (T1218.005) -- closes itself immediately, no remote content executes
Write-Host "[10/15] mshta javascript: self-close"
mshta.exe "javascript:close();"

# 11. LSASS Memory Dump signature (T1003.001) -- literal echoed text, never touches lsass.exe
Write-Host "[11/15] comsvcs.dll MiniDump signature (echo only, no real dump)"
cmd.exe /c "echo comsvcs.dll MiniDump nightowl-test>nul"

# 12. SAM/SYSTEM/SECURITY Registry Hive Dump (T1003.002) -- any resulting hive copy is deleted immediately
Write-Host "[12/15] reg.exe save hklm\sam"
$samOut = "$env:TEMP\nightowl_sam_test.hive"
reg.exe save hklm\sam $samOut 2>$null | Out-Null
Remove-Item -Path $samOut -Force -ErrorAction SilentlyContinue

# 13. RDP Lateral Movement (T1021.001) -- loopback only
Write-Host "[13/15] rdp-port loopback connection"
Invoke-LoopbackConnection -Port 3389

# 14. WinRM Lateral Movement (T1021.006) -- loopback only
Write-Host "[14/15] winrm-port loopback connection"
Invoke-LoopbackConnection -Port 5985

# 15. Lateral Movement via Windows Admin Share (T1021.002) -- loopback, deliberately wrong credentials so auth just fails
Write-Host "[15/15] net use loopback admin share (expected to fail auth)"
net.exe use \\127.0.0.1\admin$ /user:nightowltest "wrongpassword-$(Get-Random)" 2>$null | Out-Null
net.exe use \\127.0.0.1\admin$ /delete 2>$null | Out-Null

$endTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Host ""
Write-Host "=== Done. Window for export: $startTime  to  $endTime ==="
Write-Host 'wevtutil epl Microsoft-Windows-Sysmon/Operational C:\path\sysmon_malicious_demo.evtx /q:"*[System[TimeCreated[@SystemTime>=''' + $startTime + '''] and TimeCreated[@SystemTime<=''' + $endTime + ''']]]"'
