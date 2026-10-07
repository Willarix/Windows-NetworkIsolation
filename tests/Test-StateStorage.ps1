#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'NetworkIsolation.Core.ps1')
function Get-IsolationMachineId { 'test-machine' }
$testDirectory = Join-Path $PSScriptRoot ('state-storage-test-' + [guid]::NewGuid().ToString('N'))
Initialize-Isolation $testDirectory
function Assert-Test { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Expect-Error { param([scriptblock]$Code) $caught=$false; try { & $Code } catch { $caught=$true }; Assert-Test $caught 'Expected invalid state rejection' }
try {
    $state = [pscustomobject]@{Version=1; MachineId='test-machine'; Phase='Disabling'; CreatedAt='test'; UpdatedAt=''; Targets=@(
        [pscustomobject]@{Name='Ethernet'; Description='Test'; Guid='22222222-2222-2222-2222-222222222222'; PnpId='PCI\TEST'; OriginalAdminStatus=1; OriginalPnpCode=0; OriginalInterfaceIndex=22}
    )}
    Save-IsolationState $state
    Assert-Test ((Read-IsolationState).Phase -eq 'Disabling') 'Initial snapshot round-trip failed'
    $state.Phase='Isolated'; Save-IsolationState $state
    Assert-Test ((Read-IsolationState).Phase -eq 'Isolated') 'Atomic replacement failed'
    $backup=Get-Content -LiteralPath (Join-Path $script:RuntimeDirectory 'state.previous.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Test ($backup.Phase -eq 'Disabling') 'Recovery backup lost'
    $state.MachineId='another-machine'; Save-IsolationState $state
    Expect-Error { Read-IsolationState | Out-Null }
    $state.MachineId='test-machine'; $state.Targets[0].OriginalPnpCode=10; Save-IsolationState $state
    Expect-Error { Read-IsolationState | Out-Null }
    [IO.File]::WriteAllText($script:StatePath, 'invalid JSON')
    Expect-Error { Read-IsolationState | Out-Null }
    Write-Output 'PASS: actual atomic state persistence, backup, machine binding and corrupt-state rejection (6 checks).'
} finally {
    # Delete only the exact temporary files we created; no recursive or shell-composed deletion.
    foreach ($fileName in @('state.json', 'state.previous.json')) {
        $filePath=Join-Path $script:RuntimeDirectory $fileName
        if (Test-Path -LiteralPath $filePath) { Remove-Item -LiteralPath $filePath -Force }
    }
    if (Test-Path -LiteralPath $script:RuntimeDirectory) { Remove-Item -LiteralPath $script:RuntimeDirectory -Force }
    if (Test-Path -LiteralPath $testDirectory) { Remove-Item -LiteralPath $testDirectory -Force }
}
