<#
.SYNOPSIS
    This PowerShell script ensures the interactive session lock timeout is set to 900 seconds (15 minutes) by setting the InactivityTimeoutSecs policy value and applying the change.

.NOTES
    Author          : David Berrios 
    LinkedIn        : linkedin.com/in/david-b915/ 
    Date Created    : 2026-03-12
    Last Modified   : 2026-03-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000070

.TESTED ON
    Date(s) Tested  : 
    Tested By       :  
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-SO-000070).ps1 
#>

# Require elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
    exit 1
}

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "InactivityTimeoutSecs"
$valueData = 900  # seconds (15 minutes)

try {
    if (-not (Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWord -Force | Out-Null

    $current = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
    if ($current.$valueName -eq $valueData -and $current.$valueName -ne 0) {
        Write-Output "Success: $valueName set to $valueData at $regPath"
    } else {
        Write-Error "Verification failed. Current value: $($current.$valueName)"
        exit 2
    }

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
