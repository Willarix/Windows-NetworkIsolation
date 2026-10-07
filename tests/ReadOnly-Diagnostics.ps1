#Requires -Version 5.1
# READ ONLY: no Enable/Disable/Set/New/Remove networking cmdlets are invoked.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'NetworkIsolation.Core.ps1')
Initialize-Isolation (Split-Path $PSScriptRoot -Parent)
$view = Get-IsolationNetworkView
Write-Output 'Physical Wi-Fi:'
$view.Adapters | Where-Object { Test-IsolationWifiAdapter $_ } | Select-Object Name, InterfaceDescription | Format-Table -AutoSize
Write-Output 'Physical isolation targets:'
Get-IsolationPhysicalTargets $view.Adapters | Select-Object Name, InterfaceDescription, InterfaceAdminStatus | Format-Table -AutoSize
Write-Output ('Wi-Fi link and default route ready: ' + (Get-IsolationWifiReady $view))
$sample = Get-NetFirewallRule -PolicyStore ActiveStore -Action Block -ErrorAction Stop | Select-Object -First 1
$security = $sample | Get-NetFirewallSecurityFilter -ErrorAction Stop
$type = $sample | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
[pscustomobject]@{
    AuthenticationString = [string]$security.Authentication
    EncryptionString = [string]$security.Encryption
    InterfaceTypeString = [string]$type.InterfaceType
    EnabledString = [string]$sample.Enabled
    PrimaryStatusString = [string]$sample.PrimaryStatus
    ProfileString = [string]$sample.Profile
    EnforcementStatusStrings = @($sample.EnforcementStatus | ForEach-Object { [string]$_ })
} | ConvertTo-Json
Write-Output 'Read-only diagnostics completed.'
