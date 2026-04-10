<#
.SYNOPSIS
    This PowerShell script disables the Windows Installer 'Always install with elevated
    privileges' feature for both the Machine and User policy hives.

.NOTES
    Author          : Tiernan Falcon
    LinkedIn        : linkedin.com/in/tiernanfalcon/
    GitHub          : github.com/tiernanfalcon
    Date Created    : 2026-04-07
    Last Modified   : 2026-04-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    This script must be run with Administrator privileges.
    It disables the 'AlwaysInstallElevated' policy in both the HKLM and HKCU hives,
    preventing Windows Installer from installing packages with elevated (SYSTEM-level)
    privileges for all users, per STIG requirement WN11-CC-000315.

    1. Open PowerShell as Administrator.
    2. Navigate to the directory containing this script.
    3. If needed, set the execution policy:
           Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    4. Run the script:
           PS C:\> .\WN11-CC-000315.ps1

    REGISTRY CHANGES:
        Key   : HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer
        Name  : AlwaysInstallElevated
        Type  : DWORD
        Value : 0

        Key   : HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer
        Name  : AlwaysInstallElevated
        Type  : DWORD
        Value : 0
#>

# Requires elevation (Run as Administrator)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$ValueName = "AlwaysInstallElevated"
$ValueData = 0

$targets = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
)

foreach ($RegPath in $targets) {
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
        Write-Host "Successfully configured Windows Installer setting:" -ForegroundColor Green
        Write-Host "  Path  : $RegPath"
        Write-Host "  Name  : $ValueName"
        Write-Host ("  Value : {0} (0x{0:X})" -f $currentValue)
    }
    catch {
        Write-Error "Failed to configure registry setting at '$RegPath'. $_"
    }
}
