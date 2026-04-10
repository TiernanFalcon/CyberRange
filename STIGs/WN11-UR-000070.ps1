<#
.SYNOPSIS
    This PowerShell script configures the 'Deny access to this computer from the
    network' user right (SeDenyNetworkLogonRight) to include Guests and Local Accounts,
    per STIG requirement WN11-UR-000070.

.NOTES
    Author          : Tiernan Falcon
    LinkedIn        : linkedin.com/in/tiernanfalcon/
    GitHub          : github.com/tiernanfalcon
    Date Created    : 2026-04-11
    Last Modified   : 2026-04-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UR-000070

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    This script must be run with Administrator privileges.
    It configures the 'Deny access to this computer from the network' user right
    using secedit to include:
        - Guests              (S-1-5-32-546)
        - Local Accounts      (S-1-5-113)

    On domain-joined systems, highly privileged domain accounts (e.g., Domain Admins)
    should also be added via Group Policy by a domain administrator. This script
    addresses the local account and guest requirements per WN11-UR-000070.

    WARNING: Misconfiguring this right can lock out remote access to the system.
    Review the configured accounts carefully before applying in production environments.

    1. Open PowerShell as Administrator.
    2. Navigate to the directory containing this script.
    3. If needed, set the execution policy:
           Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    4. Run the script:
           PS C:\> .\WN11-UR-000070.ps1

    POLICY CHANGE (via secedit):
        Right  : SeDenyNetworkLogonRight
        SIDs   : *S-1-5-32-546 (Guests), *S-1-5-113 (Local Accounts)
#>

# Requires elevation (Run as Administrator)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$TempDir    = $env:TEMP
$ExportFile = Join-Path $TempDir "secedit_export.inf"
$ImportFile = Join-Path $TempDir "secedit_import.inf"
$DbFile     = Join-Path $TempDir "secedit_temp.sdb"

# SIDs to assign to the right:
#   S-1-5-32-546 = Guests (built-in group)
#   S-1-5-113    = Local account (well-known SID, all local accounts)
$RequiredSIDs = "*S-1-5-32-546,*S-1-5-113"
$RightName    = "SeDenyNetworkLogonRight"

try {
    # Export the current security policy to a temp INF file
    Write-Host "Exporting current security policy..."
    secedit /export /cfg $ExportFile /quiet

    if (-not (Test-Path $ExportFile)) {
        throw "secedit export failed: output file not found at '$ExportFile'."
    }

    # Read the exported policy
    $policyContent = Get-Content -Path $ExportFile -Raw

    # Check if the right already exists in the [Privilege Rights] section
    if ($policyContent -match "(?m)^$RightName\s*=\s*(.*)$") {
        $existingValue = $Matches[1].Trim()
        Write-Host "Found existing value for ${RightName}: $existingValue"

        # Parse the existing SIDs and merge with required SIDs
        $existingSIDs = $existingValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $requiredList = $RequiredSIDs -split ',' | ForEach-Object { $_.Trim() }

        $mergedSIDs = @($existingSIDs) + @($requiredList) | Sort-Object -Unique
        $newValue   = $mergedSIDs -join ','

        # Replace the existing line with the merged value
        $policyContent = $policyContent -replace "(?m)^$RightName\s*=\s*.*$", "$RightName = $newValue"
    }
    else {
        Write-Host "Right '$RightName' not found in policy. Adding it."
        # Append under [Privilege Rights] section
        $policyContent = $policyContent -replace "(\[Privilege Rights\])", "`$1`r`n$RightName = $RequiredSIDs"
    }

    # Write the modified policy to the import file
    Set-Content -Path $ImportFile -Value $policyContent -Encoding Unicode

    # Apply the modified policy using secedit
    Write-Host "Applying updated security policy..."
    secedit /configure /db $DbFile /cfg $ImportFile /quiet

    Write-Host "Successfully configured user right:" -ForegroundColor Green
    Write-Host "  Right  : $RightName"
    Write-Host "  SIDs   : $RequiredSIDs"
    Write-Host ""
    Write-Host "NOTE: On domain-joined systems, also add highly privileged domain accounts" -ForegroundColor Yellow
    Write-Host "      (e.g., Domain Admins) via Group Policy to fully satisfy WN11-UR-000070." -ForegroundColor Yellow
}
catch {
    Write-Error "Failed to configure user right '$RightName'. $_"
}
finally {
    # Clean up temp files
    foreach ($file in @($ExportFile, $ImportFile, $DbFile)) {
        if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
    }
}
