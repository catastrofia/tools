# Tools

A collection of simple, single-file scripts for Windows automation.

## PowerShell

### [block-folder-firewall](powershell/block-folder-firewall/)
Scans one or more folders for `.exe` files and creates Windows Firewall block rules (inbound + outbound) for each one. Supports WhatIf mode, duplicate detection via registry, and optional logging.

## Batch

### [choco-auto-upgrader](batch/choco-auto-upgrader/)
Runs Chocolatey to upgrade all installed packages. Designed to be scheduled as a task so program updates are handled automatically.
