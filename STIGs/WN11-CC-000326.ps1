<#
.SYNOPSIS
    This PowerShell script enables PowerShell script block logging by configuring
    the EnableScriptBlockLogging registry value, per STIG requirement WN11-CC-000326.

.NOTES
    Author          : Tiernan Falcon
    LinkedIn        : linkedin.com/in/tiernanfalcon/
    GitHub          : github.com/tiernanfalcon
    Date Created    : 2026-04-11
    Last Modified   : 2026-04-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000326

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    This script must be run with Administrator privileges.
    It will create the required registry key if it does not exist,
    then enable PowerShell script block logging per STIG requirement WN11-CC-000326.

    When enabled, Windows logs the full content of every PowerShell script block
    to the Microsoft-Windows-PowerShell/Operational event log as Event ID 4104,
    including the deobfuscated content of encoded or dynamically generated code
    at runtime. This provides significant forensic visibility into PowerShell-based
    activity, including malicious use of obfuscated payloads.

    IMPORTANT - Review before enabling:
      - Log volume will increase on systems with significant PowerShell activity.
        Ensure log retention policies and any SIEM ingestion pipelines are sized
        to handle the additional Event ID 4104 traffic.
      - Any scripts that handle credentials, keys, or other sensitive data in
        plaintext will have that content captured in the event log. Audit existing
        scripts for sensitive data exposure before enabling in production.

    Verification:
      After running, confirm logging is active by opening an elevated PowerShell
      session and running any command, then checking:

          Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' `
                       -MaxEvents 10 | Where-Object { $_.Id -eq 4104 } |
                       Select-Object TimeCreated, Message

      Event ID 4104 entries confirm script block logging is working.

    1. Open PowerShell as Administrator.
    2. Navigate to the directory containing this script.
    3. If needed, set the execution policy:
           Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    4. Run the script:
           PS C:\> .\WN11-CC-000326.ps1

    REGISTRY CHANGE:
        Key   : HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
        Name  : EnableScriptBlockLogging
        Type  : DWORD
        Value : 1
#>

# Requires elevation (Run as Administrator)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$ValueName = "EnableScriptBlockLogging"
$ValueData = 1

try {
    # Ensure the registry key exists
    if (-not (Test-Path -Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Host "Created registry key: $RegPath"
    }

    # Set the registry value
    New-ItemProperty -Path $RegPath `
                     -Name $ValueName `
                     -Value $ValueData `
                     -PropertyType DWord `
                     -Force | Out-Null

    # Read back the value for confirmation
    $currentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName).$ValueName

    # Output result
    Write-Host "Successfully configured PowerShell Script Block Logging:" -ForegroundColor Green
    Write-Host "  Path  : $RegPath"
    Write-Host "  Name  : $ValueName"
    Write-Host ("  Value : {0} (0x{0:X})" -f $currentValue)
    Write-Host ""
    Write-Host "Script block content will now be captured as Event ID 4104 in:" -ForegroundColor Cyan
    Write-Host "  Microsoft-Windows-PowerShell/Operational"
    Write-Host ""
    Write-Host "To verify logging is active, run the following after executing any PowerShell command:" -ForegroundColor Cyan
    Write-Host "  Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 10 | Where-Object { `$_.Id -eq 4104 } | Select-Object TimeCreated, Message"
}
catch {
    Write-Error "Failed to configure registry setting. $_"
}
