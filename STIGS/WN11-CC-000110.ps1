<#
.SYNOPSIS
    This PowerShell script ensures HTTP printing is disabled by setting the DisableHTTPPrinting policy to 1 and applying the change.

.NOTES
    Author          : David Berrios 
    LinkedIn        : linkedin.com/in/david-b915/ 
    Date Created    : 2026-03-07
    Last Modified   : 2026-03-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000110

.TESTED ON
    Date(s) Tested  : 
    Tested By       :  
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000110).ps1 
#>

# Ensure running elevated
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableHTTPPrinting"
$valueData = 1

try {
    # Create key if it does not exist
    if (-not (Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the DWORD value
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWord -Force | Out-Null

    # Verify
    $current = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
    if ($current.$valueName -eq $valueData) {
        Write-Output "Success: $valueName set to $valueData at $regPath"
    } else {
        Write-Error "Failed to set $valueName. Current value: $($current.$valueName)"
    }

    # Force Group Policy update (applies policy settings immediately)
    try {
        gpupdate /force | Out-Null
        Write-Output "gpupdate /force completed."
    } catch {
        Write-Warning "gpupdate failed or not available on this system: $_"
    }

    # Optional: restart Print Spooler to ensure changes take effect
    try {
        Restart-Service -Name "Spooler" -Force -ErrorAction Stop
        Write-Output "Print Spooler restarted."
    } catch {
        Write-Warning "Could not restart Print Spooler: $_"
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}

