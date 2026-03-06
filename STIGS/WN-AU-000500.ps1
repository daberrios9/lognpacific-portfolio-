<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : David Berrios 
    LinkedIn        : linkedin.com/in/david-b915/ 
    Date Created    : 2026-03-06
    Last Modified   : 2026-03-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 2026-03-06
    Tested By       : David Berrios 
    Systems Tested  : Windows VM
    PowerShell Ver. : 7.5.4

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# Ensure running elevated
if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
$propertyName = 'MaxSize'
$propertyValue = 0x8000                    # hex 00008000 = decimal 32768

# Create key (and parents) if needed, then set DWORD value
try {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    New-ItemProperty -Path $regPath -Name $propertyName -Value $propertyValue -PropertyType DWord -Force | Out-Null
    Write-Output "Set $regPath\$propertyName to 0x{0:X}" -f $propertyValue
}
catch {
    Write-Error "Failed to set registry value: $_"
    exit 1
}
