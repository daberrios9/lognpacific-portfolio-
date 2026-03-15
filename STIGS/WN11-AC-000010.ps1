<#
.SYNOPSIS
    This PowerShell script sets the Windows account lockout threshold to the specified value (default 3), enforcing account lockout after that many failed sign-in attempts (allowed values 1–3).

.NOTES
    Author          : David Berrios 
    LinkedIn        : linkedin.com/in/david-b915/ 
    Date Created    : 2026-03-08
    Last Modified   : 2026-03-08
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       :  
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AC-000010).ps1 
#>

param(
    [int]$Threshold = 3
)

# Require elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

if ($Threshold -lt 1 -or $Threshold -gt 3) {
    Write-Error "Threshold must be between 1 and 3 (0 is not allowed)."
    exit 1
}

# Apply setting
$cmd = "net accounts /lockoutthreshold:$Threshold"
$proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -NoNewWindow -Wait -PassThru

# Capture and display result
$output = (& cmd /c $cmd) -join "`n"
Write-Output $output

# Verify by parsing output
if ($output -match "Lockout threshold:\s*(\d+)") {
    $current = [int]$matches[1]
    if ($current -eq $Threshold) {
        Write-Output "Success: Account lockout threshold set to $current."
        exit 0
    } else {
        Write-Warning "Reported threshold is $current (expected $Threshold)."
        exit 2
    }
} else {
    Write-Warning "Could not determine lockout threshold from command output. Output:`n$output"
    exit 3
}

