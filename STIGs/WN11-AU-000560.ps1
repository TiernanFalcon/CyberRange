<#
.SYNOPSIS
    This PowerShell script configures Windows 11 to audit Other Logon/Logoff Events
    for Success, per STIG requirement WN11-AU-000560.

.NOTES
    Author          : Tiernan Falcon
    LinkedIn        : linkedin.com/in/tiernanfalcon/
    GitHub          : github.com/tiernanfalcon
    Date Created    : 2026-04-07
    Last Modified   : 2026-04-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000560

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    This script must be run with Administrator privileges.
    It uses auditpol.exe to enable Success auditing for the 'Other Logon/Logoff Events'
    subcategory per STIG requirement WN11-AU-000560. Auditing these events captures
    activities such as network logon sessions, reconnections, and disconnections that
    are important for detecting unauthorized access.

    1. Open PowerShell as Administrator.
    2. Navigate to the directory containing this script.
    3. If needed, set the execution policy:
           Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    4. Run the script:
           PS C:\> .\WN11-AU-000560.ps1

    AUDIT POLICY CHANGE (via auditpol.exe):
        Category    : Logon/Logoff
        Subcategory : Other Logon/Logoff Events
        Setting     : Success = Enabled
#>

# Requires elevation (Run as Administrator)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$Subcategory = "Other Logon/Logoff Events"

try {
    # Apply the audit policy using auditpol.exe
    Write-Host "Configuring audit policy for subcategory: '$Subcategory'..."
    $result = & auditpol.exe /set /subcategory:"$Subcategory" /success:enable 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "auditpol.exe returned exit code $LASTEXITCODE. Output: $result"
    }

    # Verify the setting was applied
    $verifyOutput = & auditpol.exe /get /subcategory:"$Subcategory" 2>&1
    Write-Host ""
    Write-Host "Successfully configured audit policy:" -ForegroundColor Green
    Write-Host "  Category    : Logon/Logoff"
    Write-Host "  Subcategory : $Subcategory"
    Write-Host "  Setting     : Success = Enabled"
    Write-Host ""
    Write-Host "Current policy verification:" -ForegroundColor Cyan
    $verifyOutput | ForEach-Object { Write-Host "  $_" }
}
catch {
    Write-Error "Failed to configure audit policy. $_"
}
