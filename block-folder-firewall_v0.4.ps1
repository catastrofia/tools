#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates Windows Firewall rules to block all executables in specified paths.
.DESCRIPTION
    Scans directories for .exe files and creates inbound/outbound block rules.
    Uses fast registry-based lookup to detect existing rules.
    Exit codes: 0 = success, 1 = no valid paths, 2 = one or more rules failed to create.
.PARAMETER Path
    One or more directory paths to scan for executables.
.PARAMETER SkipCheck
    Skip checking for existing rules (faster but may create duplicates).
.PARAMETER WhatIf
    Show what would be done without creating rules.
.PARAMETER LogFile
    Path to save execution log.
.PARAMETER RulePrefix
    Prefix for rule names (default: "Block").
.PARAMETER GroupName
    Group name for organizing rules in Windows Firewall UI.
.EXAMPLE
    .\block-folder-firewall_v0.4.ps1 -Path "C:\Games", "C:\Apps"
.EXAMPLE
    .\block-folder-firewall_v0.4.ps1 -Path "C:\Games" -WhatIf
.EXAMPLE
    .\block-folder-firewall_v0.4.ps1 -Path "C:\Games" -LogFile "C:\Logs\firewall.log"
#>

param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Paths to scan for executables")]
    [Alias("p")][string[]]$Path,
    [Alias("s")][switch]$SkipCheck,
    [switch]$WhatIf,
    [Alias("l")][string]$LogFile,
    [string]$RulePrefix = "Block",
    [string]$GroupName  = "Blocked Programs (Script)"
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Color = "White", [switch]$NoConsole)
    if (-not $NoConsole) { Write-Host $Message -ForegroundColor $Color }
    if ($LogFile) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $LogFile -Value "[$timestamp] $Message" -Encoding UTF8
    }
}

function Resolve-NormalizedPath {
    param([string]$PathString, [switch]$ExpandEnv)
    if ([string]::IsNullOrWhiteSpace($PathString)) { return $null }
    if ($ExpandEnv) { $PathString = [System.Environment]::ExpandEnvironmentVariables($PathString) }
    try   { return [System.IO.Path]::GetFullPath($PathString).ToLower().TrimEnd('\') }
    catch { return $PathString.ToLower().TrimEnd('\') }
}

$successCount = 0; $errorCount = 0; $skippedCount = 0
$stopwatch    = [System.Diagnostics.Stopwatch]::StartNew()
Write-Log "`n=====================================" -Color Cyan
Write-Log "   BLOCK ALL .EXE IN FOLDER V 0.4   " -Color Cyan
Write-Log "=====================================" -Color Cyan
if ($WhatIf) { Write-Log "`n[WHATIF MODE] No rules will be created`n" -Color Magenta }
Write-Log "`nValidating paths..." -Color Yellow
$validPaths = [System.Collections.Generic.List[string]]::new()
$seenPaths  = @{}
foreach ($p in $Path) {
    $normalizedP = Resolve-NormalizedPath -PathString $p
    if ($seenPaths.ContainsKey($normalizedP)) {
        Write-Log "[SKIP] Duplicate path (skipped): $p" -Color DarkYellow
        continue
    }
    if (Test-Path -Path $p -PathType Container) {
        $validPaths.Add($p)
        $seenPaths[$normalizedP] = $true
        Write-Log "[OK] Valid path: $p" -Color Green
    }
    else {
        Write-Log "[FAIL] Invalid path: $p" -Color Red
    }
}

if ($validPaths.Count -eq 0) { Write-Log "`n[FAIL] No valid paths provided." -Color Red; exit 1 }

$blockRulesLookup = @{}
if (-not $SkipCheck) {
    Write-Log "`n>> Loading firewall rules (fast registry method)..." -Color Yellow
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    try {
        $regRules  = Get-ItemProperty -Path $regPath -ErrorAction Stop
        $ruleCount = 0
        $regRules.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            $parts = @{}
            $_.Value -split '\|' | ForEach-Object {
                if ($_ -match '^([^=]+)=(.*)$') { $parts[$matches[1]] = $matches[2] }
            }
            if ($parts['Action'] -eq 'Block' -and $parts['App'] -and $parts['Active'] -ne 'FALSE') {
                $appPath = Resolve-NormalizedPath -PathString $parts['App'] -ExpandEnv
                if ($appPath) {
                    $ruleCount++
                    if (-not $blockRulesLookup.ContainsKey($appPath)) {
                        $blockRulesLookup[$appPath] = @{ 'Inbound' = $false; 'Outbound' = $false }
                    }
                    if     ($parts['Dir'] -eq 'In')  { $blockRulesLookup[$appPath]['Inbound']  = $true }
                    elseif ($parts['Dir'] -eq 'Out') { $blockRulesLookup[$appPath]['Outbound'] = $true }
                }
            }
        }
        Write-Log "[OK] Loaded $ruleCount block rules in $($stopwatch.ElapsedMilliseconds)ms" -Color Green
    }
    catch {
        Write-Log "[WARN] Registry read failed: $($_.Exception.Message)" -Color Yellow
        Write-Log "  Falling back to cmdlet method (slower)..." -Color Yellow
        try {
            Get-NetFirewallRule -Action Block -Enabled True -ErrorAction Stop | ForEach-Object {
                $appFilter = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                if ($appFilter -and $appFilter.Program -and $appFilter.Program -ne 'Any') {
                    $programPath = Resolve-NormalizedPath -PathString $appFilter.Program
                    if (-not $blockRulesLookup.ContainsKey($programPath)) {
                        $blockRulesLookup[$programPath] = @{ 'Inbound' = $false; 'Outbound' = $false }
                    }
                    if     ($_.Direction -eq 'Inbound')  { $blockRulesLookup[$programPath]['Inbound']  = $true }
                    elseif ($_.Direction -eq 'Outbound') { $blockRulesLookup[$programPath]['Outbound'] = $true }
                }
            }
            Write-Log "[OK] Loaded rules via cmdlet fallback" -Color Green
        }
        catch {
            Write-Log "[FAIL] Failed to load firewall rules: $($_.Exception.Message)" -Color Red
            Write-Log "  Continuing without duplicate detection..." -Color Yellow
        }
    }
}
else { Write-Log "`n>> Skipping rule check (fast mode)" -Color Magenta }

Write-Log "`nScanning for executables..." -Color Yellow
$exeFiles     = [System.Collections.Generic.List[PSObject]]::new()
$seenExePaths = @{}
foreach ($validPath in $validPaths) {
    Get-ChildItem -Recurse -Path $validPath -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object {
        $normalizedExePath = Resolve-NormalizedPath -PathString $_.FullName
        if (-not $seenExePaths.ContainsKey($normalizedExePath)) {
            $seenExePaths[$normalizedExePath] = $true
            $exeFiles.Add([PSCustomObject]@{
                Name           = $_.Name
                FullName       = $_.FullName
                NormalizedPath = $normalizedExePath
            })
        }
    }
}

$totalExes = $exeFiles.Count
if ($totalExes -eq 0) { Write-Log "[OK] No executables found." -Color Yellow; exit 0 }
Write-Log "[OK] Found $totalExes unique executables" -Color Green
if (-not $WhatIf -and $totalExes -gt 10) {
    Write-Host "`n[WARN] About to create firewall rules for $totalExes executables." -ForegroundColor Yellow
    $confirm = Read-Host "Continue? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Log "Operation cancelled by user." -Color Yellow; exit 0 }
}

Write-Log "`nCreating firewall rules..." -Color Cyan
$currentIndex = 0; $ruleIndex = 0
foreach ($exe in $exeFiles) {
    $currentIndex++; $exeName = $exe.Name; $exePath = $exe.FullName; $exePathNormalized = $exe.NormalizedPath
    Write-Progress -Activity "Creating firewall rules" -Status "$currentIndex of $totalExes - $exeName" -PercentComplete (($currentIndex / $totalExes) * 100)
    $hasInboundBlock = $false; $hasOutboundBlock = $false
    if (-not $SkipCheck -and $blockRulesLookup.ContainsKey($exePathNormalized)) {
        $hasInboundBlock  = $blockRulesLookup[$exePathNormalized]['Inbound']
        $hasOutboundBlock = $blockRulesLookup[$exePathNormalized]['Outbound']
    }
    if ($hasInboundBlock -and $hasOutboundBlock) {
        Write-Log "[SKIP] Already blocked: $exeName" -Color DarkYellow
        $skippedCount++
    }
    else {
        $ruleIndex++
        $sanitizedName = $exeName -replace '[<>:"/\\|?*]', '_'
        $inRuleName    = "$RulePrefix $sanitizedName In [$ruleIndex]"
        $outRuleName   = "$RulePrefix $sanitizedName Out [$ruleIndex]"
        if ($WhatIf) {
            $actions = @()
            if (-not $hasInboundBlock)  { $actions += "In" }
            if (-not $hasOutboundBlock) { $actions += "Out" }
            Write-Log "[WHATIF] Would block: $exeName [$($actions -join '/')]" -Color Cyan
            $successCount++
        }
        else {
            try {
                $createdRules = [System.Collections.Generic.List[string]]::new()
                if (-not $hasInboundBlock) {
                    New-NetFirewallRule -DisplayName $inRuleName -Direction Inbound -Program $exePath -Action Block -Group $GroupName -ErrorAction Stop | Out-Null
                    $createdRules.Add("In")
                }
                if (-not $hasOutboundBlock) {
                    New-NetFirewallRule -DisplayName $outRuleName -Direction Outbound -Program $exePath -Action Block -Group $GroupName -ErrorAction Stop | Out-Null
                    $createdRules.Add("Out")
                }
                Write-Log "[OK] Blocked: $exeName [$($createdRules -join '/')]" -Color Green
                $successCount++
            }
            catch {
                Write-Log "[FAIL] Failed: $exeName - $($_.Exception.Message)" -Color Red
                $errorCount++
            }
        }
    }
}

Write-Progress -Activity "Creating firewall rules" -Completed
$stopwatch.Stop()
Write-Log "`n========================================" -Color Cyan
Write-Log "            SUMMARY" -Color Cyan
Write-Log "========================================" -Color Cyan
Write-Log "Executables found:  $totalExes" -Color White
$blockedLabel = if ($WhatIf) { "Would block:       " } else { "Blocked:           " }
Write-Log "$blockedLabel $successCount" -Color Green
Write-Log "Skipped:            $skippedCount" -Color Yellow
Write-Log "Failed:             $errorCount" -Color Red
Write-Log "Time:               $($stopwatch.Elapsed.ToString('mm\:ss\.fff'))" -Color Cyan
Write-Log "========================================" -Color Cyan
if ($LogFile) { Write-Host "Log saved to: $LogFile" -ForegroundColor Cyan }

if (-not $WhatIf -and $successCount -gt 0) {
    Write-Log "`nTIPS:" -Color Cyan
    Write-Log "   View rules:   Get-NetFirewallRule -Group '$GroupName'" -Color DarkGray
    Write-Log "   Remove rules: Get-NetFirewallRule -Group '$GroupName' | Remove-NetFirewallRule" -Color DarkGray
}

if ($errorCount -gt 0) { exit 2 } else { exit 0 }
