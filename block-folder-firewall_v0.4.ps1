#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates Windows Firewall rules to block all executables in specified paths.

.DESCRIPTION
    Scans directories for .exe files and creates inbound/outbound block rules.
    Uses fast registry-based lookup to detect existing rules.

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
    .\Block-Programs.ps1 -Path "C:\Games", "C:\Apps"

.EXAMPLE
    .\Block-Programs.ps1 -p "C:\Games" -WhatIf

.EXAMPLE
    .\Block-Programs.ps1 -p "C:\Games" -LogFile "C:\Logs\firewall.log"
#>

param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Paths to scan for executables")]
    [Alias("p")]
    [string[]]$Path,

    [Parameter(Mandatory=$false)]
    [Alias("s")]
    [switch]$SkipCheck,

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,

    [Parameter(Mandatory=$false)]
    [Alias("l")]
    [string]$LogFile,

    [Parameter(Mandatory=$false)]
    [string]$RulePrefix = "Block",

    [Parameter(Mandatory=$false)]
    [string]$GroupName = "Blocked Programs (Script)"
)

# ============================================
# CONFIGURATION
# ============================================
$ErrorActionPreference = "Stop"
$script:LogEntries = [System.Collections.Generic.List[string]]::new()

# ============================================
# HELPER FUNCTIONS
# ============================================
function Write-Log {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    $script:LogEntries.Add($logMessage)

    if (-not $NoConsole) {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Expand-EnvironmentPath {
    <#
    .SYNOPSIS
        Expands environment variables in a path and normalizes it.
    #>
    param([string]$PathString)

    if ([string]::IsNullOrWhiteSpace($PathString)) {
        return $null
    }

    # Expand environment variables
    $expanded = [System.Environment]::ExpandEnvironmentVariables($PathString)

    # Normalize the path
    try {
        $normalized = [System.IO.Path]::GetFullPath($expanded)
        return $normalized.ToLower().TrimEnd('\')
    }
    catch {
        return $expanded.ToLower().TrimEnd('\')
    }
}

function Get-NormalizedPath {
    <#
    .SYNOPSIS
        Normalizes a filesystem path for consistent comparison.
    #>
    param([string]$PathString)

    try {
        $normalized = [System.IO.Path]::GetFullPath($PathString)
        return $normalized.ToLower().TrimEnd('\')
    }
    catch {
        return $PathString.ToLower().TrimEnd('\')
    }
}

function Save-Log {
    if ($LogFile -and $script:LogEntries.Count -gt 0) {
        try {
            $script:LogEntries | Out-File -FilePath $LogFile -Encoding UTF8
            Write-Host "Log saved to: $LogFile" -ForegroundColor Cyan
        }
        catch {
            Write-Host "Failed to save log: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ============================================
# INITIALIZATION
# ============================================
$successCount = 0
$errorCount = 0
$skippedCount = 0
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Log "`n=====================================" -Color Cyan
Write-Log "   BLOCK ALL .EXE IN FOLDER V 0.4   " -Color Cyan
Write-Log "=====================================" -Color Cyan

if ($WhatIf) {
    Write-Log "`n[WHATIF MODE] No rules will be created`n" -Color Magenta
}

# ============================================
# VALIDATE PATHS
# ============================================
Write-Log "`nValidating paths..." -Color Yellow

$validPaths = [System.Collections.Generic.List[string]]::new()
$seenPaths = @{}

foreach ($p in $Path) {
    $normalizedP = Get-NormalizedPath -PathString $p

    if ($seenPaths.ContainsKey($normalizedP)) {
        Write-Log "⊘ Duplicate path (skipped): $p" -Color DarkYellow
        continue
    }

    if (Test-Path -Path $p -PathType Container) {
        $validPaths.Add($p)
        $seenPaths[$normalizedP] = $true
        Write-Log "✓ Valid path: $p" -Color Green
    }
    else {
        Write-Log "✗ Invalid path: $p" -Color Red
    }
}

if ($validPaths.Count -eq 0) {
    Write-Log "`n✗ ERROR: No valid paths provided." -Color Red
    Save-Log
    exit 1
}

# ============================================
# FAST REGISTRY-BASED RULE LOOKUP
# ============================================
$blockRulesLookup = @{}

if (-not $SkipCheck) {
    Write-Log "`n⚡ Loading firewall rules (fast registry method)..." -Color Yellow

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"

    try {
        $regRules = Get-ItemProperty -Path $regPath -ErrorAction Stop
        $ruleCount = 0

        $regRules.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            $ruleString = $_.Value

            # Parse the pipe-delimited format
            $parts = @{}
            $ruleString -split '\|' | ForEach-Object {
                if ($_ -match '^([^=]+)=(.*)$') {
                    $parts[$matches[1]] = $matches[2]
                }
            }

            # Only track ENABLED Block rules with an App path
            $isEnabled = ($parts['Active'] -ne 'FALSE')

            if ($parts['Action'] -eq 'Block' -and $parts['App'] -and $isEnabled) {
                # Expand environment variables
                $appPath = Expand-EnvironmentPath -PathString $parts['App']

                if ($appPath) {
                    $ruleCount++

                    if (-not $blockRulesLookup.ContainsKey($appPath)) {
                        $blockRulesLookup[$appPath] = @{
                            'Inbound' = $false
                            'Outbound' = $false
                        }
                    }

                    if ($parts['Dir'] -eq 'In') {
                        $blockRulesLookup[$appPath]['Inbound'] = $true
                    }
                    elseif ($parts['Dir'] -eq 'Out') {
                        $blockRulesLookup[$appPath]['Outbound'] = $true
                    }
                }
            }
        }

        Write-Log "✓ Loaded $ruleCount block rules in $($stopwatch.ElapsedMilliseconds)ms" -Color Green
    }
    catch {
        Write-Log "⚠ Registry read failed: $($_.Exception.Message)" -Color Yellow
        Write-Log "  Falling back to cmdlet method (slower)..." -Color Yellow

        try {
            Get-NetFirewallRule -Action Block -Enabled True -ErrorAction Stop | ForEach-Object {
                $rule = $_
                $appFilter = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
                if ($appFilter -and $appFilter.Program -and $appFilter.Program -ne 'Any') {
                    $programPath = Get-NormalizedPath -PathString $appFilter.Program
                    if (-not $blockRulesLookup.ContainsKey($programPath)) {
                        $blockRulesLookup[$programPath] = @{ 'Inbound' = $false; 'Outbound' = $false }
                    }
                    if ($rule.Direction -eq 'Inbound')       { $blockRulesLookup[$programPath]['Inbound']  = $true }
                    elseif ($rule.Direction -eq 'Outbound')  { $blockRulesLookup[$programPath]['Outbound'] = $true }
                }
            }

            Write-Log "✓ Loaded rules via cmdlet fallback" -Color Green
        }
        catch {
            Write-Log "✗ Failed to load firewall rules: $($_.Exception.Message)" -Color Red
            Write-Log "  Continuing without duplicate detection..." -Color Yellow
        }
    }
}
else {
    Write-Log "`n⚡ Skipping rule check (fast mode)" -Color Magenta
}

# ============================================
# COLLECT EXE FILES (deduplicated)
# ============================================
Write-Log "`nScanning for executables..." -Color Yellow

$exeFiles = [System.Collections.Generic.List[PSObject]]::new()
$seenExePaths = @{}

foreach ($validPath in $validPaths) {
    Get-ChildItem -Recurse -Path $validPath -Filter *.exe -ErrorAction SilentlyContinue | ForEach-Object {
        $normalizedExePath = Get-NormalizedPath -PathString $_.FullName

        if (-not $seenExePaths.ContainsKey($normalizedExePath)) {
            $seenExePaths[$normalizedExePath] = $true
            $exeFiles.Add([PSCustomObject]@{
                Name = $_.Name
                FullName = $_.FullName
                NormalizedPath = $normalizedExePath
            })
        }
    }
}

$totalExes = $exeFiles.Count

if ($totalExes -eq 0) {
    Write-Log "✗ No executables found." -Color Yellow
    Save-Log
    exit 0
}

Write-Log "✓ Found $totalExes unique executables" -Color Green

# ============================================
# CONFIRMATION PROMPT
# ============================================
if (-not $WhatIf -and $totalExes -gt 10) {
    Write-Host "`n⚠ WARNING: About to create firewall rules for $totalExes executables." -ForegroundColor Yellow
    $confirm = Read-Host "Continue? (Y/N)"

    if ($confirm -notmatch '^[Yy]') {
        Write-Log "Operation cancelled by user." -Color Yellow
        Save-Log
        exit 0
    }
}

# ============================================
# PROCESS EXECUTABLES
# ============================================
Write-Log "`nCreating firewall rules..." -Color Cyan

$currentIndex = 0
$ruleIndex = 0
$createdRuleNames = [System.Collections.Generic.List[string]]::new()

foreach ($exe in $exeFiles) {
    $currentIndex++
    $exeName = $exe.Name
    $exePath = $exe.FullName
    $exePathNormalized = $exe.NormalizedPath

    Write-Progress -Activity "Creating firewall rules" -Status "$currentIndex of $totalExes - $exeName" -PercentComplete (($currentIndex / $totalExes) * 100)

    # Fast lookup using normalized path
    $hasInboundBlock = $false
    $hasOutboundBlock = $false

    if (-not $SkipCheck -and $blockRulesLookup.ContainsKey($exePathNormalized)) {
        $hasInboundBlock = $blockRulesLookup[$exePathNormalized]['Inbound']
        $hasOutboundBlock = $blockRulesLookup[$exePathNormalized]['Outbound']
    }

    if ($hasInboundBlock -and $hasOutboundBlock) {
        Write-Log "⊘ Already blocked: $exeName" -Color DarkYellow
        $skippedCount++
    }
    else {
        $ruleIndex++
        $sanitizedName = $exeName -replace '[<>:"/\\|?*]', '_'
        $inRuleName  = "$RulePrefix $sanitizedName In [$ruleIndex]"
        $outRuleName = "$RulePrefix $sanitizedName Out [$ruleIndex]"

        if ($WhatIf) {
            $actions = @()
            if (-not $hasInboundBlock) { $actions += "In" }
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
                    $createdRuleNames.Add($inRuleName)
                }

                if (-not $hasOutboundBlock) {
                    New-NetFirewallRule -DisplayName $outRuleName -Direction Outbound -Program $exePath -Action Block -Group $GroupName -ErrorAction Stop | Out-Null
                    $createdRules.Add("Out")
                    $createdRuleNames.Add($outRuleName)
                }

                Write-Log "✓ Blocked: $exeName [$($createdRules -join '/')]" -Color Green
                $successCount++
            }
            catch {
                Write-Log "✗ Failed: $exeName - $($_.Exception.Message)" -Color Red
                $errorCount++
            }
        }
    }
}

Write-Progress -Activity "Creating firewall rules" -Completed

# ============================================
# SUMMARY
# ============================================
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

if (-not $WhatIf -and $createdRuleNames.Count -gt 0) {
    Write-Log "`n💡 TIPS:" -Color Cyan
    Write-Log "   View rules:   Get-NetFirewallRule -Group '$GroupName'" -Color DarkGray
    Write-Log "   Remove rules: Get-NetFirewallRule -Group '$GroupName' | Remove-NetFirewallRule" -Color DarkGray
}

# Save log if specified
Save-Log

# Exit with appropriate code
if ($errorCount -gt 0) {
    exit 2
}
else {
    exit 0
}
