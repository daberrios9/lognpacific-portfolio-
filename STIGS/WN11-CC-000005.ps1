<#
.SYNOPSIS
    This PowerShell script ensures the lock screen camera is disabled by setting the NoLockScreenCamera policy to 1 and applying the change.

.NOTES
    Author          : David Berrios 
    LinkedIn        : linkedin.com/in/david-b915/ 
    Date Created    : 2026-03-12
    Last Modified   : 2026-03-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       :  
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000005).ps1 
#>

# Require elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName = "NoLockScreenCamera"
$valueData = 1

try {
    # Create key if missing
    if (-not (Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Create or update DWORD value
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWord -Force | Out-Null

    # Verify
    $current = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
    if ($current.$valueName -eq $valueData) {
        Write-Output "Success: $valueName set to $valueData at $regPath"
    } else {
        Write-Error "Verification failed. Current value: $($current.$valueName)"
        exit 2
    }

    # Refresh Group Policy (optional)
    try {
        gpupdate /force | Out-Null
        Write-Output "gpupdate /force invoked."
    } catch {
        Write-Warning "gpupdate failed or not available: $_"
    }
}
catch {
    Write-Error "Error: $_"
    exit 1
}
