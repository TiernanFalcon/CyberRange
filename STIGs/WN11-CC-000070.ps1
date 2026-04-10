<#
.SYNOPSIS
    This PowerShell script enables Virtualization-based Security (VBS) and configures
    the platform security level to Secure Boot with DMA Protection (if IOMMU is present)
    or Secure Boot only (if IOMMU is absent), per STIG requirement WN11-CC-000070.

.NOTES
    Author          : Tiernan Falcon
    LinkedIn        : linkedin.com/in/tiernanfalcon/
    GitHub          : github.com/tiernanfalcon
    Date Created    : 2026-04-07
    Last Modified   : 2026-04-11
    Version         : 2.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000070

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    This script must be run with Administrator privileges.
    It performs the following steps:

      1. PRE-FLIGHT CHECK — Queries the current VBS status via WMI. If VBS is
         already running (status 2), no changes are made and the script exits.

      2. HARDWARE CAPABILITY CHECK — Detects whether the system has IOMMU support
         (Intel VT-d / AMD-Vi). Sets RequirePlatformSecurityFeatures to:
             3 = Secure Boot + DMA Protection  (if IOMMU is present)
             1 = Secure Boot only              (if IOMMU is absent)
         Both values satisfy STIG WN11-CC-000070.

      3. REGISTRY CHANGES — Writes the VBS settings to the DeviceGuard registry key.

      4. REBOOT PROMPT — Prompts the user to restart immediately, as a reboot is
         required before VBS changes take effect. Restart can be deferred.

    PREREQUISITES:
      - 64-bit processor with virtualization extensions (Intel VT-x / AMD-V)
      - UEFI firmware with Secure Boot enabled
      - TPM 1.2 or higher recommended
      - Hardware-based IOMMU (Intel VT-d / AMD-Vi) for full DMA Protection

    POST-REBOOT VERIFICATION:
      After restarting, run the following command in an elevated PowerShell session
      to confirm VBS is active:

          Get-WmiObject -Class Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning

      VirtualizationBasedSecurityStatus values:
          0 = Not enabled
          1 = Enabled but not running  (check UEFI Secure Boot / IOMMU settings)
          2 = Running                  (VBS is active and protecting the system)

      If the status returns 1 after reboot, verify that Secure Boot and (if applicable)
      VT-d / AMD-Vi are enabled in the system UEFI firmware settings.

    1. Open PowerShell as Administrator.
    2. Navigate to the directory containing this script.
    3. If needed, set the execution policy:
           Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    4. Run the script:
           PS C:\> .\WN11-CC-000070.ps1

    REGISTRY CHANGES:
        Key   : HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard
        Name  : EnableVirtualizationBasedSecurity
        Type  : DWORD
        Value : 1 (Enabled)

        Key   : HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard
        Name  : RequirePlatformSecurityFeatures
        Type  : DWORD
        Value : 3 (Secure Boot + DMA Protection) if IOMMU detected
                1 (Secure Boot only)             if IOMMU not detected
#>

# Requires elevation (Run as Administrator)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# -------------------------------------------------------------------
# STEP 1 - PRE-FLIGHT CHECK
# Query current VBS status. If already running, no changes are needed.
# -------------------------------------------------------------------

Write-Host "Checking current Virtualization-based Security status..." -ForegroundColor Cyan

$deviceGuard = $null

try {
    $deviceGuard = Get-WmiObject -Class Win32_DeviceGuard `
                                 -Namespace root\Microsoft\Windows\DeviceGuard `
                                 -ErrorAction Stop

    $vbsStatus = $deviceGuard.VirtualizationBasedSecurityStatus

    switch ($vbsStatus) {
        2 {
            Write-Host "VBS is already running on this system. No changes required." -ForegroundColor Green
            Write-Host "  VirtualizationBasedSecurityStatus : $vbsStatus (Running)"
            exit 0
        }
        1 { Write-Host "  VirtualizationBasedSecurityStatus : $vbsStatus (Enabled but not running -- will apply settings)" -ForegroundColor Yellow }
        0 { Write-Host "  VirtualizationBasedSecurityStatus : $vbsStatus (Not enabled -- will apply settings)" -ForegroundColor Yellow }
        default { Write-Host "  VirtualizationBasedSecurityStatus : $vbsStatus (Unknown -- will attempt to apply settings)" -ForegroundColor Yellow }
    }
}
catch {
    Write-Warning "Could not query Win32_DeviceGuard WMI class. Proceeding with configuration. ($_)"
}

Write-Host ""

# -------------------------------------------------------------------
# STEP 2 - HARDWARE CAPABILITY CHECK
# Detect IOMMU support to determine the correct platform security level.
# AvailableSecurityProperties value 3 indicates DMA protection is available.
# -------------------------------------------------------------------

Write-Host "Checking for IOMMU (DMA Protection) hardware support..." -ForegroundColor Cyan

$iommuPresent = $false

try {
    if ($deviceGuard -and $deviceGuard.AvailableSecurityProperties -contains 3) {
        $iommuPresent = $true
    }
}
catch {
    Write-Warning "Could not determine IOMMU support from WMI. Defaulting to Secure Boot only. ($_)"
}

if ($iommuPresent) {
    $platformSecurityLevel = 3
    Write-Host "  IOMMU detected. Setting platform security level to: 3 (Secure Boot + DMA Protection)" -ForegroundColor Green
}
else {
    $platformSecurityLevel = 1
    Write-Host "  IOMMU not detected. Setting platform security level to: 1 (Secure Boot only)" -ForegroundColor Yellow
    Write-Host "  Both values satisfy STIG WN11-CC-000070." -ForegroundColor Yellow
}

Write-Host ""

# -------------------------------------------------------------------
# STEP 3 - APPLY REGISTRY SETTINGS
# -------------------------------------------------------------------

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"

$settings = @(
    @{ Name = "EnableVirtualizationBasedSecurity"; Value = 1;                     Description = "VBS Enabled" },
    @{ Name = "RequirePlatformSecurityFeatures";   Value = $platformSecurityLevel; Description = "Platform Security Level" }
)

try {
    # Ensure the registry key exists
    if (-not (Test-Path -Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Host "Created registry key: $RegPath"
    }

    foreach ($setting in $settings) {
        New-ItemProperty -Path $RegPath `
                         -Name $setting.Name `
                         -Value $setting.Value `
                         -PropertyType DWord `
                         -Force | Out-Null

        $currentValue = (Get-ItemProperty -Path $RegPath -Name $setting.Name).($setting.Name)

        Write-Host "Successfully configured VBS setting ($($setting.Description)):" -ForegroundColor Green
        Write-Host "  Path  : $RegPath"
        Write-Host "  Name  : $($setting.Name)"
        Write-Host ("  Value : {0} (0x{0:X})" -f $currentValue)
        Write-Host ""
    }
}
catch {
    Write-Error "Failed to configure VBS registry settings. $_"
}

# -------------------------------------------------------------------
# STEP 4 - REBOOT PROMPT
# VBS changes require a restart to take effect.
# -------------------------------------------------------------------

Write-Host "A system restart is required for Virtualization-based Security to take effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "After restarting, verify VBS is running with:" -ForegroundColor Cyan
Write-Host "  Get-WmiObject -Class Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning"
Write-Host ""
Write-Host "  Status 2 = Running (success)"
Write-Host "  Status 1 = Enabled but not running (check UEFI Secure Boot / IOMMU firmware settings)"
Write-Host ""

$response = Read-Host "Restart now? (Y/N)"

if ($response -match "^[Yy]$") {
    Write-Host "Restarting system in 10 seconds. Close any open work now..." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
else {
    Write-Host "Restart deferred. Remember to reboot before verifying VBS status." -ForegroundColor Yellow
}
