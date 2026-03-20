# Block Folder Firewall

A PowerShell script that scans directories for `.exe` files and creates Windows Firewall block rules (inbound + outbound) for each one.

## Requirements

- Windows 10/11
- PowerShell 5.1+
- Administrator privileges

## Usage

```powershell
.\block-folder-firewall_v0.3.ps1 -Path "C:\Games"
.\block-folder-firewall_v0.3.ps1 -Path "C:\Games", "C:\Apps"
```

## Parameters

| Parameter | Alias | Description |
|-----------|-------|-------------|
| `-Path` | `-p` | One or more directories to scan (required) |
| `-SkipCheck` | `-s` | Skip duplicate rule detection (faster, may create duplicates) |
| `-WhatIf` | | Preview what would be done without creating rules |
| `-LogFile` | `-l` | Path to save a timestamped log file |
| `-RulePrefix` | | Prefix for rule names (default: `Block`) |
| `-GroupName` | | Group name in Windows Firewall UI (default: `Blocked Programs (Script)`) |

## Examples

```powershell
# Preview without making changes
.\block-folder-firewall_v0.3.ps1 -Path "C:\Games" -WhatIf

# Block all exes in a folder and save a log
.\block-folder-firewall_v0.3.ps1 -Path "C:\Games" -LogFile "C:\Logs\firewall.log"

# Skip duplicate detection for faster execution
.\block-folder-firewall_v0.3.ps1 -Path "C:\Games" -SkipCheck
```

## How It Works

1. Validates the provided paths
2. Loads existing firewall block rules via the registry (fast) or `Get-NetFirewallRule` (fallback)
3. Scans the directories recursively for `.exe` files
4. Prompts for confirmation if more than 10 executables are found
5. Creates inbound and outbound block rules, skipping any already blocked

## Managing Created Rules

```powershell
# View all rules created by this script
Get-NetFirewallRule -Group "Blocked Programs (Script)"

# Remove all rules created by this script
Get-NetFirewallRule -Group "Blocked Programs (Script)" | Remove-NetFirewallRule
```
