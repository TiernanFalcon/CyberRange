<#
.SYNOPSIS
    This PowerShell script enables the use of audit policy subcategories by setting
    the SCENoApplyLegacyAuditPolicy registry value, per STIG requirement WN11-SO-000030.

.NOTES
    Author          : Tiernan Falcon
    LinkedIn        : linkedin.com/in/tiernanfalcon/
    GitHub          : github.com/tiernanfalcon
    Date Created    : 2026-04-11
    Last Modified   : 2026-04-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000030

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    This script must be run with Administrator privileges.
    It will create the required registry key if it does not exist,
    then enable audit policy subcategory enforcement per STIG requirement
    WN11-SO-000030.

    By default, Windows allows category-level audit policy settings to override
    subcategory settings. Enabling this value forces subcategory settings (as
    configured via auditpol.exe or Group Policy audit subcategories) to take
    precedence. This is required for granular audit policies -- such as those
    required by other STIGs like WN11-AU-000560 -- to function correctly.

    NOTE: This setting should be applied before or alongside any auditpol-based
    STIG scripts to ensure subcategory audit policies are not silently overridden
    by legacy category-level policy.

    1. Open PowerShell as Administrator.
    2. Navigate to the directory containing this script.
    3. If needed, set the execution policy:
           Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    4. Run the script:
           PS C:\> .\WN11-SO-000030.ps1

    REGISTRY CHANGE:
        Key   : HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
        Name  : SCENoApplyLegacyAuditPolicy
        Type  : DWORD
        Value : 1
#>

# Requires elevation (Run as Administrator)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$RegPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"
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
    Write-Host "Successfully configured audit subcategory policy setting:" -ForegroundColor Green
    Write-Host "  Path  : $RegPath"
    Write-Host "  Name  : $ValueName"
    Write-Host ("  Value : {0} (0x{0:X})" -f $currentValue)
    Write-Host ""
    Write-Host "Subcategory audit policies will now take precedence over category-level settings." -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to configure registry setting. $_"
}
