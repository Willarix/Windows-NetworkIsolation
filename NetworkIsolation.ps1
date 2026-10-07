#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Disable', 'Restore', 'Check', 'Inspect')][string]$Action = 'Menu',
    [switch]$Pause
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $shellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Action {1}' -f $PSCommandPath, $Action
        if ($Pause) { $arguments += ' -Pause' }
        # A visible console is intentional: this is the user's interactive switch and result display.
        $child = Start-Process -FilePath $shellPath -Verb RunAs -ArgumentList $arguments -Wait -PassThru
        exit $child.ExitCode
    } catch {
        Write-Host ('未获得管理员权限，未修改网络：' + $_.Exception.Message) -ForegroundColor Red
        if ($Pause) { $null = Read-Host '按 Enter 退出' }
        exit 1
    }
}

. (Join-Path $PSScriptRoot 'NetworkIsolation.Core.ps1')
Initialize-Isolation -BaseDirectory $PSScriptRoot
$mutex = New-Object Threading.Mutex($false, 'Global\Codex.NetworkIsolation.v1')
$locked = $false
$exitCode = 0
try {
    try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw '另一个网络隔离窗口正在执行，请等待它完成后再操作。' }
    if ($Action -eq 'Menu') {
        $done = $false
        while (-not $done) {
            Write-Host ''
            Write-Host '========== 有线网络隔离 ==========' -ForegroundColor Cyan
            Write-Host '1  禁用有线：设置阻断 + 禁用实体设备 + 核验'
            Write-Host '2  恢复有线：恢复本工具保存的原始状态'
            Write-Host '3  检查当前隔离状态（不切换网络）'
            Write-Host '0  退出（保留当前状态）'
            Write-Host '禁用前关闭需要隔离的应用；等核验通过后再打开。'
            $choice = Read-Host '请选择'
            try {
                switch ($choice) {
                    '1' { Show-IsolationVerification (Invoke-IsolationDisable) }
                    '2' { Invoke-IsolationRestore; Write-Host '【已恢复】有线设备恢复到禁用前状态。连接网线后由 Windows 选择路由。' -ForegroundColor Green }
                    '3' { Show-IsolationVerification (Get-IsolationVerification (Read-IsolationState)) }
                    '0' { $done = $true }
                    default { Write-Host '请输入 1、2、3 或 0。' }
                }
            } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
        }
    } else {
        switch ($Action) {
            'Disable' { Show-IsolationVerification (Invoke-IsolationDisable) }
            'Restore' { Invoke-IsolationRestore; Write-Host '【已恢复】有线设备恢复到禁用前状态。连接网线后由 Windows 选择路由。' -ForegroundColor Green }
            'Check' {
                $result = Get-IsolationVerification (Read-IsolationState)
                Show-IsolationVerification $result
                if (-not $result.Safe) { $exitCode = 1 }
            }
            'Inspect' {
                $view = Get-IsolationNetworkView
                $view.Adapters | Where-Object HardwareInterface |
                    Select-Object Name, InterfaceDescription, HardwareInterface, InterfaceAdminStatus, NdisMedium, NdisPhysicalMedium |
                    Format-Table -AutoSize | Out-Host
                Write-Host ('识别到 {0} 个需禁用的实体非 Wi-Fi 设备。' -f @(Get-IsolationPhysicalTargets $view.Adapters).Count)
                $view.Routes | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } |
                    Select-Object InterfaceAlias, DestinationPrefix, NextHop | Format-Table -AutoSize | Out-Host
            }
        }
    }
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    $exitCode = 1
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
if ($Pause -and $Action -ne 'Menu') { $null = Read-Host '按 Enter 关闭窗口（保留当前网络状态）' }
exit $exitCode
