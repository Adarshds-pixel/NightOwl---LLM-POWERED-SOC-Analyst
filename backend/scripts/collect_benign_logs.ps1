<#
.SYNOPSIS
    Enable and export benign Windows telemetry for the NightOwl ML baseline.

.DESCRIPTION
    The ML anomaly layer fits only on benign telemetry. The current corpus is
    two hosts with almost no Sysmon EID 3, which is why 42 of 70 features have
    too little support to model (see ML.md section 2). This script fixes that
    at the source.

    Run it in two passes, days apart:

      1.  -Setup    (as Administrator, once per machine)
          Installs Sysmon, turns on PowerShell script-block logging and
          command-line process auditing, and enlarges the logs so a week of
          data does not roll over.

      2.  ... then USE THE MACHINE NORMALLY for 3-7 days. Browse, code,
          install things, run PowerShell. The point is to capture what normal
          looks like, so do not curate your behaviour.

      3.  -Export   (as Administrator)
          Writes .evtx files named for this host into -OutDir.

    PRIVACY: Sysmon logs every command line, file path and network
    destination. That includes your usernames, directory names and the hosts
    you connect to. These files land in a git repository. Read what you are
    about to commit, and do not run this on a machine handling anything you
    would not publish.

.EXAMPLE
    # One-time, elevated:
    .\collect_benign_logs.ps1 -Setup

    # Days later, elevated:
    .\collect_benign_logs.ps1 -Export

.EXAMPLE
    # Undo the logging changes when you are done collecting:
    .\collect_benign_logs.ps1 -Revert
#>

[CmdletBinding(DefaultParameterSetName = 'Export')]
param(
    [Parameter(ParameterSetName = 'Setup')]
    [switch]$Setup,

    [Parameter(ParameterSetName = 'Export')]
    [switch]$Export,

    [Parameter(ParameterSetName = 'Revert')]
    [switch]$Revert,

    # Where the .evtx files go. Default is the benign dataset itself.
    [string]$OutDir = (Join-Path $PSScriptRoot '..\sample_logs\real_world_fixtures\NightOwl-Benign-Dataset'),

    # Sysmon channel size in MB. 1024 holds roughly a week of ordinary desktop
    # use; raise it if -Export warns that the log has wrapped.
    [int]$SysmonLogSizeMB = 1024
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This needs an elevated PowerShell. Right-click PowerShell -> Run as Administrator."
    }
}

# Deliberately permissive. Hardening configs (SwiftOnSecurity, Olaf Hartong)
# filter out routine activity to cut noise -- which is exactly backwards for a
# benign baseline, where the routine activity IS the signal we are modelling.
# The two exclusions below are purely about log volume: ImageLoad and
# unfiltered ProcessAccess would fill the channel in hours and add almost
# nothing the feature set reads.
$SysmonConfig = @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- EID 1: process creation. Feeds process/command-line/LOLBin/parent-child features. -->
    <RuleGroup groupRelation="or"><ProcessCreate onmatch="exclude" /></RuleGroup>

    <!-- EID 3: network connections. THE missing feature family -- all four
         network columns are currently zero across all 1829 benign windows. -->
    <RuleGroup groupRelation="or"><NetworkConnect onmatch="exclude" /></RuleGroup>

    <!-- EID 10: process access, narrowed to lsass. Unfiltered this is the
         noisiest event Sysmon emits; scoped here it gives the real benign
         rate of lsass access (AV and LSM do it constantly), which is what
         the lsass_access feature needs a baseline for. -->
    <RuleGroup groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- EID 11: file creation. -->
    <RuleGroup groupRelation="or"><FileCreate onmatch="exclude" /></RuleGroup>

    <!-- EID 12/13/14: registry. Feeds uac_bypass and accessibility features. -->
    <RuleGroup groupRelation="or"><RegistryEvent onmatch="exclude" /></RuleGroup>

    <!-- EID 18: named pipes. Feeds remote_named_pipe. -->
    <RuleGroup groupRelation="or"><PipeEvent onmatch="exclude" /></RuleGroup>

    <!-- EID 7 (ImageLoad) and EID 22 (DNS) are intentionally NOT enabled:
         very high volume, and the feature set reads almost nothing from them. -->
  </EventFiltering>
</Sysmon>
'@

function Find-Sysmon {
    <# PATH first, then the usual unzip spots. Returns $null if not found. #>
    $onPath = Get-Command sysmon64.exe, sysmon.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) { return $onPath.Source }

    $candidates = @(
        "$env:USERPROFILE\Tools\Sysmon\Sysmon64.exe"
        "$env:USERPROFILE\Downloads\Sysmon\Sysmon64.exe"
        "$env:USERPROFILE\Downloads\Sysmon64.exe"
        "$PSScriptRoot\Sysmon64.exe"
        "C:\Tools\Sysmon\Sysmon64.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return (Resolve-Path $c).Path } }
    return $null
}

function Invoke-Setup {
    Assert-Admin
    $failed = @()

    Write-Host "`n=== 1/4  Sysmon ===" -ForegroundColor Cyan

    # Not finding Sysmon must NOT abort the rest of setup: the PowerShell,
    # auditpol and log-size steps are independent and still worth applying.
    # An earlier version returned here and silently skipped all three.
    $sysmon = Find-Sysmon
    if (-not $sysmon) {
        Write-Host "  Sysmon not found. Download and unzip it, then re-run -Setup:" -ForegroundColor Yellow
        Write-Host "    https://learn.microsoft.com/sysinternals/downloads/sysmon"
        Write-Host "    Put Sysmon64.exe on PATH or in $env:USERPROFILE\Tools\Sysmon\"
        Write-Host "  Continuing with the other steps." -ForegroundColor Yellow
        $failed += "Sysmon (binary not found)"
    } else {
        Write-Host "  Using $sysmon"
        $configPath = Join-Path $env:TEMP 'nightowl-sysmon.xml'
        $SysmonConfig | Set-Content -Path $configPath -Encoding utf8

        $installed = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue
        if ($installed) {
            Write-Host "  Already installed; applying the baseline config."
            & $sysmon -c $configPath
        } else {
            Write-Host "  Installing with the baseline config (accepting EULA)."
            & $sysmon -accepteula -i $configPath
        }
        if ($LASTEXITCODE -ne 0) { $failed += "Sysmon (exit code $LASTEXITCODE)" }
    }

    Write-Host "`n=== 2/4  PowerShell script-block logging (EID 4104) ===" -ForegroundColor Cyan
    $psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $psKey)) { New-Item -Path $psKey -Force | Out-Null }
    Set-ItemProperty -Path $psKey -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
    Write-Host "  EnableScriptBlockLogging = 1"

    Write-Host "`n=== 3/4  Command line in process-creation events (4688) ===" -ForegroundColor Cyan
    # Sysmon EID 1 already carries command lines; this makes the Security
    # channel match, which matters because roughly half the attack fixtures
    # are Security-only captures with no Sysmon at all.
    auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $auditKey)) { New-Item -Path $auditKey -Force | Out-Null }
    Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
    Write-Host "  Process Creation auditing = on, command line included"

    Write-Host "`n=== 4/4  Log sizes ===" -ForegroundColor Cyan
    $sizes = @{
        'Microsoft-Windows-Sysmon/Operational'    = $SysmonLogSizeMB * 1MB
        'Security'                                = 512MB
        'Microsoft-Windows-PowerShell/Operational' = 256MB
        'System'                                  = 128MB
        'Application'                             = 128MB
    }
    foreach ($channel in $sizes.Keys) {
        try {
            wevtutil sl "$channel" /ms:$($sizes[$channel])
            Write-Host ("  {0,-45} {1} MB" -f $channel, ($sizes[$channel] / 1MB))
        } catch {
            Write-Host "  skipped $channel (not present on this machine)" -ForegroundColor DarkGray
        }
    }

    # Re-read the real state rather than trusting that the commands above
    # worked. Every one of these is readable without elevation, so you can
    # re-check at any time -- and a half-applied setup is worse than none,
    # because you would collect for a week before noticing.
    Write-Host "`n=== Verification ===" -ForegroundColor Cyan
    $checks = [ordered]@{}

    $svc = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue
    $checks['Sysmon service running'] = ($svc -and $svc.Status -eq 'Running')

    try {
        $checks['Sysmon channel present'] = [bool](Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop)
    } catch { $checks['Sysmon channel present'] = $false }

    $psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $checks['PowerShell 4104 logging'] =
        (Get-ItemProperty -Path $psKey -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1

    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    $checks['4688 includes command line'] =
        (Get-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled -eq 1

    $checks['Process Creation auditing'] = ((auditpol /get /subcategory:"Process Creation") -join ' ') -match 'Success'

    foreach ($k in $checks.Keys) {
        if ($checks[$k]) { Write-Host ("  [ OK ] {0}" -f $k) -ForegroundColor Green }
        else             { Write-Host ("  [FAIL] {0}" -f $k) -ForegroundColor Red }
    }

    if ($checks.Values -contains $false) {
        Write-Host "`nSETUP INCOMPLETE -- do not start the collection window yet." -ForegroundColor Red
        if ($failed) { Write-Host ("Problems: {0}" -f ($failed -join '; ')) -ForegroundColor Red }
        Write-Host "Fix the [FAIL] items above and re-run -Setup. It is safe to run repeatedly."
        return
    }

    Write-Host "`nSetup complete and verified." -ForegroundColor Green
    Write-Host "Now use this machine NORMALLY for 3-7 days, then run:  .\collect_benign_logs.ps1 -Export"
    Write-Host "Do not curate your behaviour -- ordinary use is the whole point." -ForegroundColor Yellow
}

function Invoke-Export {
    Assert-Admin
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $resolved = (Resolve-Path $OutDir).Path
    $host_tag = $env:COMPUTERNAME.ToLower() -replace '[^a-z0-9]', '_'
    $stamp = Get-Date -Format 'yyyyMMdd'

    $channels = @{
        'sysmon'     = 'Microsoft-Windows-Sysmon/Operational'
        'security'   = 'Security'
        'powershell' = 'Microsoft-Windows-PowerShell/Operational'
        'system'     = 'System'
        'application' = 'Application'
    }

    Write-Host "`nExporting to $resolved" -ForegroundColor Cyan
    $any = $false
    foreach ($name in $channels.Keys) {
        $channel = $channels[$name]
        $info = $null
        try { $info = Get-WinEvent -ListLog $channel -ErrorAction Stop } catch {
            Write-Host ("  {0,-12} channel not present; skipped" -f $name) -ForegroundColor DarkGray
            continue
        }
        if ($info.RecordCount -eq 0) {
            Write-Host ("  {0,-12} empty; skipped" -f $name) -ForegroundColor DarkGray
            continue
        }

        $out = Join-Path $resolved "${host_tag}_${name}_${stamp}.evtx"
        if (Test-Path $out) { Remove-Item $out -Force }
        wevtutil epl "$channel" "$out"

        $mb = [math]::Round((Get-Item $out).Length / 1MB, 1)
        Write-Host ("  {0,-12} {1,8} records  {2,7} MB  -> {3}" -f $name, $info.RecordCount, $mb, (Split-Path $out -Leaf))
        $any = $true

        # A log at its size cap has wrapped, so the oldest events are gone and
        # the capture covers less time than you think.
        if ($info.FileSize -ge ($info.MaximumSizeInBytes * 0.98)) {
            Write-Host ("     WARNING: {0} is at its size cap and has wrapped. Raise -SysmonLogSizeMB and recollect." -f $name) -ForegroundColor Yellow
        }
    }

    if (-not $any) { Write-Host "`nNothing exported. Did you run -Setup and then wait a few days?" -ForegroundColor Red; return }

    Write-Host "`nNext, from backend/:" -ForegroundColor Green
    Write-Host "  # scripts/cache is keyed per file -- the 31 existing captures load from"
    Write-Host "  # it instantly and only your new .evtx files get parsed. Leave it alone."
    Write-Host "  ./venv/Scripts/python.exe scripts/extract_ml_features.py"
    Write-Host "  ./venv/Scripts/python.exe scripts/train_ml_model.py   # watch the dropped-feature list shrink"
    Write-Host "  ./venv/Scripts/python.exe scripts/eval_ml_model.py"
    Write-Host "`nBefore committing, read what you are about to publish: these files contain" -ForegroundColor Yellow
    Write-Host "your command lines, file paths and network destinations." -ForegroundColor Yellow
}

function Invoke-Revert {
    Assert-Admin
    Write-Host "Reverting the logging changes (exported .evtx files are left alone)." -ForegroundColor Cyan

    $sysmon = Get-Command sysmon64.exe, sysmon.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sysmon -and (Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue)) {
        & $sysmon.Source -u
        Write-Host "  Sysmon uninstalled"
    }

    $psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (Test-Path $psKey) {
        Set-ItemProperty -Path $psKey -Name 'EnableScriptBlockLogging' -Value 0 -Type DWord
        Write-Host "  Script-block logging off"
    }

    auditpol /set /subcategory:"Process Creation" /success:disable | Out-Null
    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (Test-Path $auditKey) {
        Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 0 -Type DWord
    }
    Write-Host "  Process-creation auditing off"
    Write-Host "`nLog size caps left as-is; they are harmless." -ForegroundColor DarkGray
}

switch ($PSCmdlet.ParameterSetName) {
    'Setup'  { Invoke-Setup }
    'Revert' { Invoke-Revert }
    default  { Invoke-Export }
}
