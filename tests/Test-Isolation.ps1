#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'NetworkIsolation.Core.ps1')
Initialize-Isolation (Split-Path $PSScriptRoot -Parent)
$script:passed = 0

function Assert-Test { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Expect-Error { param([scriptblock]$Code) $caught = $false; try { & $Code } catch { $caught = $true }; Assert-Test $caught 'Expected an error, but operation succeeded.' }
function Test-Case { param([string]$Name, [scriptblock]$Code) Reset-Test; & $Code; $script:passed++; Write-Output ('PASS: ' + $Name) }

function New-TestAdapter {
    param([string]$Name, [string]$Guid, [string]$PnpId, [int]$Index, [bool]$Wifi = $false, [bool]$Hardware = $true)
    [pscustomobject]@{ Name=$Name; InterfaceDescription=$Name; InterfaceGuid=$Guid; PnPDeviceID=$PnpId; ifIndex=$Index;
        HardwareInterface=$Hardware; NdisPhysicalMedium=$(if ($Wifi) {9} else {14}); NdisMedium=$(if ($Wifi) {16} else {0});
        InterfaceAdminStatus=1; Status='Up' }
}
function Reset-Test {
    $script:events = New-Object 'System.Collections.Generic.List[string]'
    $script:testState = $null
    $script:firewall = $false
    $script:firewallFailure = $false
    $script:saveFailure = $false
    $script:disableFailure = ''
    $script:netDisableFailure = $false
    $script:enableFailure = ''
    $script:removeFailure = $false
    $script:lingeringRoute = $false
    $script:adapters = @(
        (New-TestAdapter 'WLAN' '11111111-1111-1111-1111-111111111111' 'PCI\WIFI' 11 $true),
        (New-TestAdapter 'Ethernet' '22222222-2222-2222-2222-222222222222' 'PCI\WIRED' 22),
        (New-TestAdapter 'VPN' '33333333-3333-3333-3333-333333333333' 'ROOT\VPN' 33 $false $false)
    )
    $script:pnpCodes = @{ 'PCI\WIFI'=0; 'PCI\WIRED'=0; 'ROOT\VPN'=0 }
}

# Simulated OS boundaries only. Real flow, classifier, verification and restore functions run unchanged.
function Get-IsolationMachineId { 'test-machine' }
function Read-IsolationState { $script:testState }
function Save-IsolationState {
    param($State)
    if ($script:saveFailure) { throw 'Simulated disk write failure' }
    $script:events.Add('Save:' + $State.Phase)
    $script:testState = $State | ConvertTo-Json -Depth 8 | ConvertFrom-Json
}
function Write-IsolationLog { param($Message) }
function Get-IsolationAdapters { @($script:adapters) }
function Get-IsolationPnpCode { param($PnpId) if (-not $script:pnpCodes.ContainsKey($PnpId)) { throw 'Device absent' }; [int]$script:pnpCodes[$PnpId] }
function Ensure-IsolationFirewall { $script:events.Add('Block'); if ($script:firewallFailure) { throw 'Simulated firewall refusal' }; $script:firewall=$true }
function Assert-IsolationFirewall { if (-not $script:firewall) { throw 'Firewall not effective' } }
function Get-IsolationRules { param($Store) if ($script:firewall) { [pscustomobject]@{Name='mock'} } }
function Remove-IsolationFirewall { $script:events.Add('Unblock'); $script:firewall=$false; if ($script:removeFailure) { throw 'Partial rule removal failed' } }
function Disable-NetAdapter {
    [CmdletBinding(SupportsShouldProcess)]param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        $script:events.Add('NetOff:' + $InputObject.PnPDeviceID)
        if ($script:netDisableFailure) { throw 'Simulated interface error' }
        $InputObject.InterfaceAdminStatus=2; $InputObject.Status='Disabled'
    }
}
function Enable-NetAdapter {
    [CmdletBinding(SupportsShouldProcess)]param([Parameter(ValueFromPipeline)]$InputObject)
    process { $script:events.Add('NetOn:' + $InputObject.PnPDeviceID); $InputObject.InterfaceAdminStatus=1; $InputObject.Status='Disconnected' }
}
function Disable-PnpDevice {
    [CmdletBinding(SupportsShouldProcess)]param($InstanceId)
    $script:events.Add('PnpOff:' + $InstanceId)
    if ($InstanceId -eq $script:disableFailure) { throw 'Simulated PnP refusal' }
    $script:pnpCodes[$InstanceId]=22
    foreach ($adapter in $script:adapters) { if ($adapter.PnPDeviceID -eq $InstanceId) { $adapter.InterfaceAdminStatus=2; $adapter.Status='Disabled' } }
}
function Enable-PnpDevice {
    [CmdletBinding(SupportsShouldProcess)]param($InstanceId)
    $script:events.Add('PnpOn:' + $InstanceId)
    if ($InstanceId -eq $script:enableFailure) { throw 'Simulated restore error' }
    $script:pnpCodes[$InstanceId]=0
}
function Get-IsolationNetworkView {
    $interfaces = @(); $routes = @()
    foreach ($adapter in $script:adapters) {
        if ($adapter.InterfaceAdminStatus -eq 1) {
            $interfaces += [pscustomobject]@{InterfaceIndex=$adapter.ifIndex; ConnectionState='Connected'}
            $routes += [pscustomobject]@{InterfaceIndex=$adapter.ifIndex; InterfaceAlias=$adapter.Name; DestinationPrefix='0.0.0.0/0'; NextHop='test'}
        }
    }
    if ($script:lingeringRoute) { $routes += [pscustomobject]@{InterfaceIndex=22; InterfaceAlias='Ethernet'; DestinationPrefix='::/0'; NextHop='test'} }
    [pscustomobject]@{Adapters=@($script:adapters); Interfaces=$interfaces; Routes=$routes}
}
function Wait-IsolationVerification { param($State, $TimeoutSeconds) Get-IsolationVerification $State }

Test-Case 'snapshot, firewall, interface, device ordering; Wi-Fi and tunnel retained' {
    $result = Invoke-IsolationDisable
    Assert-Test $result.Safe 'Isolation not verified'
    Assert-Test ($script:events[0] -eq 'Save:Disabling') 'Network changed before recovery snapshot'
    Assert-Test ($script:events.IndexOf('Block') -lt $script:events.IndexOf('NetOff:PCI\WIRED')) 'Interface disabled before firewall'
    Assert-Test ($script:pnpCodes['PCI\WIFI'] -eq 0 -and $script:pnpCodes['ROOT\VPN'] -eq 0) 'Wi-Fi/VPN was modified'
    Assert-Test ($script:testState.Phase -eq 'Isolated') 'Missing verified state'
}
Test-Case 'interface command failure still disables device' {
    $script:netDisableFailure=$true
    $result=Invoke-IsolationDisable
    Assert-Test ($result.Safe -and $script:pnpCodes['PCI\WIRED'] -eq 22) 'Device fallback not applied'
}
Test-Case 'firewall refusal still attempts device disable and never reports success' {
    $script:firewallFailure=$true
    Expect-Error { Invoke-IsolationDisable | Out-Null }
    Assert-Test ($script:pnpCodes['PCI\WIRED'] -eq 22) 'Device was not disabled'
    Assert-Test ($script:testState.Phase -eq 'Faulted') 'Unsafe result persisted as success'
    Assert-Test (-not (@($script:events | Where-Object { $_ -like '*On:*' }).Count)) 'Failure reopened a device'
}
Test-Case 'device failure does not skip remaining adapters' {
    $script:adapters += New-TestAdapter 'USB Ethernet' '44444444-4444-4444-4444-444444444444' 'USB\WIRED' 44
    $script:pnpCodes['USB\WIRED']=0; $script:disableFailure='PCI\WIRED'
    Expect-Error { Invoke-IsolationDisable | Out-Null }
    Assert-Test ($script:pnpCodes['USB\WIRED'] -eq 22 -and $script:firewall) 'Second device or firewall skipped'
}
Test-Case 'IPv6 residual route prevents success' {
    $script:lingeringRoute=$true
    Expect-Error { Invoke-IsolationDisable | Out-Null }
    Assert-Test ($script:testState.Phase -eq 'Faulted') 'Residual route passed'
}
Test-Case 'Wi-Fi loss keeps isolation and does not enable wired fallback' {
    $script:adapters[0].Status='Disconnected'; $script:adapters[0].InterfaceAdminStatus=2
    $result=Invoke-IsolationDisable
    Assert-Test ($result.Safe -and -not $result.WifiReady -and $script:pnpCodes['PCI\WIRED'] -eq 22) 'Wi-Fi failure reopened wired'
}
Test-Case 'repeated disable preserves original snapshot; restore works after rename' {
    $null=Invoke-IsolationDisable
    $script:adapters[1].Name='Renamed adapter'
    $null=Invoke-IsolationDisable
    Assert-Test ($script:testState.Targets[0].OriginalAdminStatus -eq 1) 'Original state overwritten'
    Invoke-IsolationRestore
    Assert-Test ($script:adapters[1].InterfaceAdminStatus -eq 1 -and $script:pnpCodes['PCI\WIRED'] -eq 0 -and -not $script:firewall) 'Restore failed'
    Assert-Test ($script:events.IndexOf('PnpOn:PCI\WIRED') -lt $script:events.IndexOf('Unblock')) 'Firewall removed before device restore'
}
Test-Case 'originally disabled device remains disabled on restore' {
    $script:adapters[1].InterfaceAdminStatus=2; $script:adapters[1].Status='Disabled'; $script:pnpCodes['PCI\WIRED']=22
    $null=Invoke-IsolationDisable; Invoke-IsolationRestore
    Assert-Test ($script:pnpCodes['PCI\WIRED'] -eq 22) 'Originally disabled device enabled'
}
Test-Case 'originally disabled interface with enabled PnP device is preserved' {
    $script:adapters[1].InterfaceAdminStatus=2; $script:adapters[1].Status='Disabled'
    $null=Invoke-IsolationDisable; Invoke-IsolationRestore
    Assert-Test ($script:pnpCodes['PCI\WIRED'] -eq 0 -and $script:adapters[1].InterfaceAdminStatus -eq 2) 'Original interface admin status lost'
}
Test-Case 'partial device restore failure closes already restored adapters' {
    $script:adapters += New-TestAdapter 'USB Ethernet' '44444444-4444-4444-4444-444444444444' 'USB\WIRED' 44
    $script:pnpCodes['USB\WIRED']=0; $null=Invoke-IsolationDisable; $script:enableFailure='USB\WIRED'
    Expect-Error { Invoke-IsolationRestore }
    Assert-Test ($script:pnpCodes['PCI\WIRED'] -eq 22 -and $script:pnpCodes['USB\WIRED'] -eq 22 -and $script:firewall) 'Partial restore left wired enabled'
    Assert-Test ($script:events -notcontains 'Unblock') 'Firewall removed on restore failure'
}
Test-Case 'partial firewall removal failure rebuilds blockers and disables devices' {
    $null=Invoke-IsolationDisable; $script:removeFailure=$true
    Expect-Error { Invoke-IsolationRestore }
    Assert-Test ($script:firewall -and $script:pnpCodes['PCI\WIRED'] -eq 22 -and $script:testState.Phase -eq 'Faulted') 'Removal failure left open device'
}
Test-Case 'snapshot write failure changes no networking' {
    $script:saveFailure=$true
    Expect-Error { Invoke-IsolationDisable | Out-Null }
    Assert-Test ($script:events.Count -eq 0 -and -not $script:firewall -and $script:pnpCodes['PCI\WIRED'] -eq 0) 'Mutation before durable state'
}
Test-Case 'missing snapshot cannot remove protections or enable devices' {
    $script:firewall=$true
    Expect-Error { Invoke-IsolationRestore }
    Assert-Test ($script:firewall -and $script:events.Count -eq 0) 'Restore guessed original state'
}
Test-Case 'a new device introduced after isolation invalidates verification' {
    $null=Invoke-IsolationDisable
    $script:adapters += New-TestAdapter 'New USB' '44444444-4444-4444-4444-444444444444' 'USB\NEW' 44
    $result=Get-IsolationVerification $script:testState
    Assert-Test (-not $result.Safe) 'New device did not invalidate verification'
}
Test-Case 'a device re-enabled externally invalidates verification' {
    $null=Invoke-IsolationDisable; $script:pnpCodes['PCI\WIRED']=0
    $result=Get-IsolationVerification $script:testState
    Assert-Test (-not $result.Safe) 'External device re-enable passed'
}
Test-Case 'device hidden after PnP disable still checks its previous route index' {
    $null=Invoke-IsolationDisable
    $script:adapters=@($script:adapters | Where-Object PnPDeviceID -ne 'PCI\WIRED')
    $script:lingeringRoute=$true
    Assert-Test (-not (Get-IsolationVerification $script:testState).Safe) 'Missing device ignored its residual route'
}
Test-Case 'identity mismatch prevents restore' {
    $null=Invoke-IsolationDisable; $script:adapters[1].PnPDeviceID='PCI\REPLACED'
    Expect-Error { Invoke-IsolationRestore }
    Assert-Test ($script:events -notcontains 'PnpOn:PCI\WIRED') 'Mismatched device enabled'
}
Test-Case 'restored record does not claim active isolation' {
    $null=Invoke-IsolationDisable; Invoke-IsolationRestore
    Assert-Test (-not (Get-IsolationVerification $script:testState).Safe) 'Restored mode claims isolation'
}
Test-Case 'unknown physical medium is included; virtual Ethernet is excluded' {
    $script:adapters[1].NdisPhysicalMedium=0
    $targets=@(Get-IsolationPhysicalTargets $script:adapters)
    Assert-Test ($targets.Count -eq 1 -and $targets[0].PnPDeviceID -eq 'PCI\WIRED') 'Unsafe adapter classification'
}
Write-Output ('All {0} simulated safety tests passed. No real adapter/firewall mutation was invoked.' -f $script:passed)
