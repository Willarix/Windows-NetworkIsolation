#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'NetworkIsolation.Core.ps1')
Initialize-Isolation (Split-Path $PSScriptRoot -Parent)
$script:passed=0
function Assert-Test { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Expect-Error { param([scriptblock]$Code) $caught=$false; try { & $Code } catch { $caught=$true }; Assert-Test $caught 'Expected firewall verification failure' }
function Reset-Test {
    $script:profiles=@('Domain','Private','Public') | ForEach-Object { [pscustomobject]@{Name=$_; Enabled='True'; AllowLocalFirewallRules='True'; DisabledInterfaceAliases=$null} }
    $script:rules=@(0..1 | ForEach-Object { [pscustomobject]@{Name=$script:RuleNames[$_]; Group=$script:RuleGroup; Enabled='True'; Action='Block'; Direction=@('Outbound','Inbound')[$_]; Profile='Any'; PrimaryStatus='OK'; EnforcementStatus=@('Enforced')} })
    $script:type=[pscustomobject]@{InterfaceType='Wired'}
    $script:iface=[pscustomobject]@{InterfaceAlias='Any'}
    $script:address=[pscustomobject]@{LocalAddress='Any'; RemoteAddress='Any'}
    $script:port=[pscustomobject]@{Protocol='Any'; LocalPort='Any'; RemotePort='Any'}
    $script:app=[pscustomobject]@{Program='Any'; Package=$null}
    $script:svc=[pscustomobject]@{Service='Any'}
    $script:security=[pscustomobject]@{Authentication='NotRequired'; Encryption='NotRequired'; OverrideBlockRules=$false; LocalUser='Any'; RemoteUser='Any'; RemoteMachine='Any'}
    $script:bypass=@(); $script:serviceRunning=$true
}
function Test-Case { param($Name, [scriptblock]$Code) Reset-Test; & $Code; $script:passed++; Write-Output ('PASS: ' + $Name) }
function Get-Service { [CmdletBinding()]param($Name) [pscustomobject]@{Status=$(if ($script:serviceRunning) {'Running'} else {'Stopped'})} }
function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore) $script:profiles }
function Get-IsolationRules { param($Store) $script:rules }
function Get-NetFirewallRule { [CmdletBinding()]param($PolicyStore, $Enabled, $Action) $script:bypass }
function Get-NetFirewallInterfaceTypeFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { $script:type } }
function Get-NetFirewallInterfaceFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { $script:iface } }
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { $script:address } }
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { $script:port } }
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { $script:app } }
function Get-NetFirewallServiceFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { $script:svc } }
function Get-NetFirewallSecurityFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject) process { $script:security } }

Test-Case 'complete broad wired rules pass' { Assert-IsolationFirewall }
Test-Case 'stopped firewall service rejected' { $script:serviceRunning=$false; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'disabled firewall profile rejected' { $script:profiles[0].Enabled='False'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'group policy disabling local-rule merge rejected' { $script:profiles[1].AllowLocalFirewallRules='False'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'interface firewall exemption rejected' { $script:profiles[1].DisabledInterfaceAliases=@('Ethernet'); Expect-Error { Assert-IsolationFirewall } }
Test-Case 'missing inbound blocker rejected' { $script:rules=@($script:rules[0]); Expect-Error { Assert-IsolationFirewall } }
Test-Case 'disabled blocker rejected' { $script:rules[0].Enabled='False'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'inactive/unapplied blocker rejected' { $script:rules[0].EnforcementStatus=@('LocalFirewallRulesDisallowed'); Expect-Error { Assert-IsolationFirewall } }
Test-Case 'wireless interface type cannot masquerade as wired blocker' { $script:type.InterfaceType='Wireless'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'renamable adapter alias restriction rejected' { $script:iface.InterfaceAlias='Ethernet'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'IPv4-only scope rejected' { $script:address.RemoteAddress='0.0.0.0/0'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'TCP-only scope rejected' { $script:port.Protocol='TCP'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'application-limited blocker rejected' { $script:app.Program='test.exe'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'user-limited blocker rejected' { $script:security.LocalUser='restricted'; Expect-Error { Assert-IsolationFirewall } }
Test-Case 'authenticated bypass rule rejected' { $script:bypass=@([pscustomobject]@{Name='bypass'}); $script:security.OverrideBlockRules=$true; Expect-Error { Assert-IsolationFirewall } }
Write-Output ('All {0} firewall verification tests passed. No real firewall changes were invoked.' -f $script:passed)
