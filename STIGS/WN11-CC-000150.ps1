<#
.SYNOPSIS
    This PowerShell script ensures a specific AC power policy setting is enabled by setting its registry policy value to 1 and applying the change.

.NOTES
    Author          : David Berrios 
    LinkedIn        : linkedin.com/in/david-b915/ 
    Date Created    : 2026-03-08
    Last Modified   : 2026-03-08
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000150

.TESTED ON
    Date(s) Tested  : 
    Tested By       :  
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000150).ps1 
#>

# Require elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$valueName = "ACSettingIndex"
$valueData = 1

try {
    # Create key if missing
    if (-not (Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the DWORD value
    Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type DWord -Force

    # Verify
    $current = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
    if ($current.$valueName -eq $valueData) {
        Write-Output "Success: $valueName set to $valueData at $regPath"
    } else {
        Write-Error "Verification failed. Current value: $($current.$valueName)"
        exit 2
    }

    # Force Group Policy refresh (optional but recommended)
    try {
        gpupdate /force | Out-Null
        Write-Output "gpupdate /force completed."
    } catch {
        Write-Warning "gpupdate failed or not available: $_"
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
