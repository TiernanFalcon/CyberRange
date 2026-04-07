<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Tiernan Falcon
    LinkedIn        : linkedin.com/in/tiernanfalcon/
    GitHub          : github.com/tiernanfalcon
    Date Created    : 2026-03-31
    Last Modified   : 2026-03-31
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    This script must be run with Administrator privileges.
    It will create the required registry key if it does not exist,
    then set the Application event log maximum size to 32768 KB (32 MB)
    per STIG requirement WN11-AU-000500.

    1. Open PowerShell as Administrator.
    2. Navigate to the directory containing this script.
    3. If needed, set the execution policy:
           Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    4. Run the script:
           PS C:\> .\WN11-AU-000500.ps1

    REGISTRY CHANGE:
        Key   : HKLM:\SOFTWARE\Policies\Microsoft\EventLog\Application
        Name  : MaxSize
        Type  : DWORD
        Value : 0x8000 (32768)
#>

# Requires elevation (Run as Administrator)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegPath   = "HKLM:\SOFTWARE\Policies\Microsoft\EventLog\Application"
$ValueName = "MaxSize"
$ValueData = 0x8000  # 32768 KB

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
    Write-Host "Successfully configured Event Log setting:" -ForegroundColor Green
    Write-Host "  Path  : $RegPath"
    Write-Host "  Name  : $ValueName"
    Write-Host ("  Value : {0} (0x{0:X})" -f $currentValue)
}
catch {
    Write-Error "Failed to configure registry setting. $_"
}
