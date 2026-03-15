<#
.SYNOPSIS
    This PowerShell script renames the built-in Windows Guest account to a specified name (default "LocalGuestRenamed") and verifies the change.

.NOTES
    Author          : David Berrios 
    LinkedIn        : linkedin.com/in/david-b915/ 
    Date Created    : 2026-03-11
    Last Modified   : 2026-03-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000025

.TESTED ON
    Date(s) Tested  : 
    Tested By       :  
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-SO-000025).ps1 
#>

param(
    [string]$NewName = "LocalGuestRenamed"
)

# Require elevation
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

if ([string]::IsNullOrWhiteSpace($NewName)) {
    Write-Error "NewName cannot be empty."
    exit 1
}

if ($NewName -ieq "Guest") {
    Write-Error 'NewName cannot be "Guest". Choose a different name.'
    exit 1
}

# Ensure LocalAccounts module/cmdlets available (Windows 10/Server 2016+)
if (-not (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue)) {
    Write-Error "Local user management cmdlets not available on this system."
    exit 1
}

# Find built-in Guest account by well-known RID (501)
try {
    $guest = Get-LocalUser | Where-Object {
        try {
            ($_ | Get-LocalUser).Sid.Value -match "-501$"
        } catch {
            $false
        }
    }
} catch {
    Write-Error "Failed to enumerate local users: $_"
    exit 1
}

if (-not $guest) {
    # alternative method: check SIDs directly
    $guest = Get-LocalUser | Where-Object { $_.Sid.Value -match "-501$" }
}

if (-not $guest) {
    Write-Error "Built-in Guest account (RID 501) not found on this system."
    exit 1
}

# If target name already exists and is not the guest account, fail
$existing = Get-LocalUser -Name $NewName -ErrorAction SilentlyContinue
if ($existing -and ($existing.Sid.Value -notmatch "-501$")) {
    Write-Error "A different account already exists with the name '$NewName'. Choose another name."
    exit 1
}

try {
    Rename-LocalUser -Name $guest.Name -NewName $NewName
    Write-Output "Renamed built-in Guest account from '$($guest.Name)' to '$NewName'."

    # Verify
    $verify = Get-LocalUser | Where-Object { $_.Sid.Value -match "-501$" }
    if ($verify -and $verify.Name -ieq $NewName) {
        Write-Output "Verification successful: Guest account name is now '$NewName'."
        exit 0
    } else {
        Write-Warning "Rename attempted but verification failed. Current account: $($verify.Name)"
        exit 2
    }
} catch {
    Write-Error "Failed to rename Guest account: $_"
    exit 1
}
