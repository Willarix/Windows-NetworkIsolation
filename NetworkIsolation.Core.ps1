# Windows PowerShell 5.1 / PowerShell 7. Functions only; dot-sourcing does not change networking.
Set-StrictMode -Version Latest

function Initialize-Isolation {
    param([Parameter(Mandatory)][string]$BaseDirectory)
    $script:RuntimeDirectory = Join-Path $BaseDirectory 'runtime'
    $script:StatePath = Join-Path $script:RuntimeDirectory 'state.json'
    $script:RuleGroup = 'Codex NetworkIsolation v1'
    $script:RuleNames = @('Codex.NetworkIsolation.v1.Wired.Out', 'Codex.NetworkIsolation.v1.Wired.In')
}

function Get-IsolationMachineId {
    [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
}

function Write-IsolationLog {
    param([string]$Message)
    try {
        if (-not (Test-Path -LiteralPath $script:RuntimeDirectory)) {
            New-Item -ItemType Directory -Path $script:RuntimeDirectory -Force -ErrorAction Stop | Out-Null
        }
        $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'), $Message
        Add-Content -LiteralPath (Join-Path $script:RuntimeDirectory 'activity.log') -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch { Write-Warning ('无法写入日志：' + $_.Exception.Message) }
}

function Read-IsolationState {
    if (-not (Test-Path -LiteralPath $script:StatePath)) { return $null }
    $state = Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($state.Version -ne 1 -or $state.MachineId -ne (Get-IsolationMachineId)) {
        throw '状态文件版本不正确或属于另一台电脑。禁止自动恢复。'
    }
    if ($state.Phase -notin @('Disabling', 'Isolated', 'Faulted', 'Restoring', 'Restored')) {
        throw '状态文件的阶段无效。禁止自动恢复。'
    }
    $seen = @{}
    foreach ($target in @($state.Targets)) {
        $parsedGuid = [guid]::Empty
        if (-not [guid]::TryParse([string]$target.Guid, [ref]$parsedGuid) -or
            [string]::IsNullOrWhiteSpace([string]$target.PnpId) -or
            $target.OriginalPnpCode -notin @(0, 22) -or
            $target.OriginalAdminStatus -notin @(1, 2) -or [int]$target.OriginalInterfaceIndex -le 0 -or
            $seen.ContainsKey([string]$target.PnpId)) {
            throw '状态文件中的设备记录无效。禁止自动恢复。'
        }
        $seen[[string]$target.PnpId] = $true
    }
    if (@($state.Targets).Count -eq 0) { throw '状态文件没有设备记录。' }
    return $state
}

function Save-IsolationState {
    param([Parameter(Mandatory)]$State)
    New-Item -ItemType Directory -Path $script:RuntimeDirectory -Force -ErrorAction Stop | Out-Null
    $State.UpdatedAt = [DateTime]::UtcNow.ToString('o')
    $json = $State | ConvertTo-Json -Depth 8
    $tempPath = Join-Path $script:RuntimeDirectory ('state.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($tempPath, $json, (New-Object Text.UTF8Encoding($true)))
        if (Test-Path -LiteralPath $script:StatePath) {
            # Atomic replacement: a terminated process leaves either the old or the new snapshot.
            [IO.File]::Replace($tempPath, $script:StatePath, (Join-Path $script:RuntimeDirectory 'state.previous.json'))
        } else { [IO.File]::Move($tempPath, $script:StatePath) }
    } finally {
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue }
    }
}

function Get-IsolationAdapters { @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) }

function Test-IsolationWifiAdapter {
    param($Adapter)
    # NDIS physical medium: 1 Wireless LAN, 9 Native 802.11; NDIS medium: 16 Native 802.11.
    return ($Adapter.HardwareInterface -eq $true -and
        ([int]$Adapter.NdisPhysicalMedium -in @(1, 9) -or [int]$Adapter.NdisMedium -eq 16))
}

function Get-IsolationPhysicalTargets {
    param([object[]]$Adapters)
    # Unknown physical media are conservatively included. Names, languages and link status are not identifiers.
    @($Adapters | Where-Object { $_.HardwareInterface -eq $true -and -not (Test-IsolationWifiAdapter $_) })
}

function Get-IsolationPnpCode {
    param([Parameter(Mandatory)][string]$PnpId)
    $device = @(Get-PnpDevice -InstanceId $PnpId -PresentOnly -ErrorAction Stop)
    if ($device.Count -ne 1 -or $device[0].Class -ne 'Net') { throw ('不是当前存在的网络设备：' + $PnpId) }
    $property = Get-PnpDeviceProperty -InstanceId $PnpId -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction Stop
    [int]$property.Data
}

function New-IsolationTarget {
    param($Adapter)
    if ([string]::IsNullOrWhiteSpace([string]$Adapter.PnPDeviceID)) { throw ('设备缺少 PnP 标识：' + $Adapter.Name) }
    $code = Get-IsolationPnpCode -PnpId $Adapter.PnPDeviceID
    $adminStatus = [int]$Adapter.InterfaceAdminStatus
    if ($code -notin @(0, 22) -or $adminStatus -notin @(1, 2)) {
        throw ('设备原始状态异常，无法安全保存恢复记录：' + $Adapter.Name)
    }
    [pscustomobject]@{
        Name = [string]$Adapter.Name
        Description = [string]$Adapter.InterfaceDescription
        Guid = ([guid]$Adapter.InterfaceGuid).ToString('D')
        PnpId = [string]$Adapter.PnPDeviceID
        OriginalAdminStatus = $adminStatus
        OriginalPnpCode = $code
        OriginalInterfaceIndex = [int]$Adapter.ifIndex
    }
}

function Find-IsolationAdapter {
    param([object[]]$Adapters, $Target)
    $matches = @($Adapters | Where-Object { ([string]$_.InterfaceGuid).Trim('{}') -eq $Target.Guid })
    if ($matches.Count -gt 1) { throw '同一设备 GUID 出现了多个网卡，无法核验。' }
    if ($matches.Count -eq 1) {
        if ($matches[0].PnPDeviceID -ne $Target.PnpId -or -not $matches[0].HardwareInterface -or
            (Test-IsolationWifiAdapter $matches[0])) { throw ('设备身份发生变化：' + $Target.Name) }
        return $matches[0]
    }
    return $null
}

function Get-IsolationRules {
    param([ValidateSet('PersistentStore', 'ActiveStore')][string]$Store)
    @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop | Where-Object { $_.Name -in $script:RuleNames })
}

function Ensure-IsolationFirewall {
    # Do not silently alter global firewall settings, domain policy or unrelated rules.
    $existing = @(Get-IsolationRules -Store PersistentStore)
    foreach ($i in 0..1) {
        $direction = @('Outbound', 'Inbound')[$i]
        $match = @($existing | Where-Object Name -eq $script:RuleNames[$i])
        if ($match.Count -gt 0) {
            if ($match.Count -ne 1 -or $match[0].Group -ne $script:RuleGroup) { throw '同名防火墙规则不属于本工具，已停止修改。' }
            # Never delete an existing blocker before recreating it.
            Set-NetFirewallRule -PolicyStore PersistentStore -Name $script:RuleNames[$i] -Enabled True -Profile Any `
                -Direction $direction -Action Block -InterfaceType Wired -InterfaceAlias Any `
                -Protocol Any -LocalAddress Any -RemoteAddress Any -LocalPort Any -RemotePort Any `
                -Program Any -Service Any -ErrorAction Stop
        } else {
            New-NetFirewallRule -PolicyStore PersistentStore -Name $script:RuleNames[$i] `
                -DisplayName ('网络隔离：阻断有线 ' + $direction) -Group $script:RuleGroup `
                -Description 'NetworkIsolation: persistent IPv4/IPv6 wired traffic block; remove with the restore action.' `
                -Enabled True -Profile Any -Direction $direction -Action Block -InterfaceType Wired `
                -Protocol Any -LocalAddress Any -RemoteAddress Any -ErrorAction Stop | Out-Null
        }
    }
}

function Test-IsolationAny {
    param($Value)
    $items = @($Value)
    return ($items.Count -eq 1 -and [string]$items[0] -eq 'Any')
}

function Assert-IsolationFirewall {
    foreach ($serviceName in @('BFE', 'MpsSvc')) {
        if ((Get-Service -Name $serviceName -ErrorAction Stop).Status -ne 'Running') { throw ('防火墙服务未运行：' + $serviceName) }
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -ne 3) { throw '无法读取全部三个防火墙配置文件。' }
    foreach ($profile in $profiles) {
        if ([string]$profile.Enabled -ne 'True' -or [string]$profile.AllowLocalFirewallRules -eq 'False' -or
            @($profile.DisabledInterfaceAliases | Where-Object { $_ -and $_ -ne 'NotConfigured' }).Count -gt 0) {
            throw ('防火墙被关闭、规则合并被禁用或存在接口豁免：' + $profile.Name)
        }
    }
    $rules = @(Get-IsolationRules -Store ActiveStore)
    foreach ($i in 0..1) {
        $match = @($rules | Where-Object Name -eq $script:RuleNames[$i])
        if ($match.Count -ne 1) { throw ('有效策略中缺少唯一阻断规则：' + $script:RuleNames[$i]) }
        $rule = $match[0]
        $enforcement = @($rule.EnforcementStatus | ForEach-Object { [string]$_ })
        if ($rule.Group -ne $script:RuleGroup -or [string]$rule.Enabled -ne 'True' -or
            [string]$rule.Action -ne 'Block' -or [string]$rule.Direction -ne @('Outbound', 'Inbound')[$i] -or
            [string]$rule.Profile -ne 'Any' -or [string]$rule.PrimaryStatus -ne 'OK' -or
            $enforcement -notcontains 'Enforced' -or
            @($enforcement | Where-Object { $_ -notin @('Enforced', 'ProfileInactive') }).Count -gt 0) {
            throw ('阻断规则未完整生效：' + $rule.Name)
        }
        $type = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
        $iface = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
        $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
        $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
        $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        $svc = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
        $security = $rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
        if ([string]$type.InterfaceType -ne 'Wired' -or -not (Test-IsolationAny $iface.InterfaceAlias) -or
            -not (Test-IsolationAny $address.LocalAddress) -or -not (Test-IsolationAny $address.RemoteAddress) -or
            [string]$port.Protocol -ne 'Any' -or -not (Test-IsolationAny $port.LocalPort) -or
            -not (Test-IsolationAny $port.RemotePort) -or -not (Test-IsolationAny $app.Program) -or
            ($app.Package -and [string]$app.Package -ne 'Any') -or -not (Test-IsolationAny $svc.Service) -or
            [string]$security.Authentication -ne 'NotRequired' -or [string]$security.Encryption -ne 'NotRequired' -or
            $security.OverrideBlockRules -eq $true -or -not (Test-IsolationAny $security.LocalUser) -or
            -not (Test-IsolationAny $security.RemoteUser) -or -not (Test-IsolationAny $security.RemoteMachine)) {
            throw ('阻断规则包含范围限制，不能认为所有有线流量均被阻断：' + $rule.Name)
        }
    }
    # Authenticated bypass rules can override blocks. Fail the supplemental firewall check if present.
    $bypass = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow -ErrorAction Stop |
        Get-NetFirewallSecurityFilter -ErrorAction Stop | Where-Object OverrideBlockRules -eq $true)
    if ($bypass.Count -gt 0) { throw '发现允许绕过阻断的认证规则，无法确认防火墙保护完整。' }
}

function Disable-IsolationTarget {
    param($Target)
    $adapter = Find-IsolationAdapter -Adapters @(Get-IsolationAdapters) -Target $Target
    # Always try device-level disable, even when Disable-NetAdapter reports an error.
    if ($null -ne $adapter -and [int]$adapter.InterfaceAdminStatus -ne 2) {
        try { $adapter | Disable-NetAdapter -Confirm:$false -ErrorAction Stop }
        catch { Write-IsolationLog ('接口禁用失败，将继续禁用实体设备：' + $Target.Name + ' / ' + $_.Exception.Message) }
    }
    if ((Get-IsolationPnpCode -PnpId $Target.PnpId) -ne 22) {
        Disable-PnpDevice -InstanceId $Target.PnpId -Confirm:$false -ErrorAction Stop
    }
}

function Get-IsolationNetworkView {
    [pscustomobject]@{
        Adapters = @(Get-IsolationAdapters)
        Interfaces = @(Get-NetIPInterface -ErrorAction Stop)
        Routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
    }
}

function Assert-IsolationDevices {
    param($State, $View)
    $knownIds = @($State.Targets | ForEach-Object PnpId)
    $indices = @()
    foreach ($current in @(Get-IsolationPhysicalTargets -Adapters $View.Adapters)) {
        if ($current.PnPDeviceID -notin $knownIds) { throw ('发现未纳入本轮隔离的新实体设备：' + $current.Name) }
        $indices += [int]$current.ifIndex
    }
    foreach ($target in @($State.Targets)) {
        if ((Get-IsolationPnpCode -PnpId $target.PnpId) -ne 22) { throw ('实体设备未禁用（需要设备问题代码 22）：' + $target.Name) }
        $adapter = Find-IsolationAdapter -Adapters $View.Adapters -Target $target
        if ($null -ne $adapter) {
            $indices += [int]$adapter.ifIndex
            if ([int]$adapter.InterfaceAdminStatus -ne 2 -or [string]$adapter.Status -eq 'Up') {
                throw ('有线接口仍处于启用状态：' + $target.Name)
            }
        } elseif (@($View.Adapters | Where-Object { [int]$_.ifIndex -eq $target.OriginalInterfaceIndex }).Count -eq 0) {
            # Some drivers remove MSFT_NetAdapter after PnP disable. Still check its last known route index.
            $indices += [int]$target.OriginalInterfaceIndex
        }
    }
    $connected = @($View.Interfaces | Where-Object { $_.InterfaceIndex -in $indices -and [string]$_.ConnectionState -eq 'Connected' })
    $routes = @($View.Routes | Where-Object { $_.InterfaceIndex -in $indices })
    if ($connected.Count -gt 0 -or $routes.Count -gt 0) { throw '实体有线接口仍有连接或活动路由（包括 IPv4/IPv6），核验失败。' }
}

function Get-IsolationWifiReady {
    param($View)
    $wifi = @($View.Adapters | Where-Object { (Test-IsolationWifiAdapter $_) -and [string]$_.Status -eq 'Up' })
    $indices = @($wifi | ForEach-Object { [int]$_.ifIndex })
    $interfaces = @($View.Interfaces | Where-Object { $_.InterfaceIndex -in $indices -and [string]$_.ConnectionState -eq 'Connected' })
    $routes = @($View.Routes | Where-Object { $_.InterfaceIndex -in $indices -and $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') })
    return ($wifi.Count -gt 0 -and $interfaces.Count -gt 0 -and $routes.Count -gt 0)
}

function Get-IsolationVerification {
    param($State)
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $view = $null
    if ($null -eq $State -or $State.Phase -eq 'Restored') { $errors.Add('当前没有有效的隔离状态记录。') }
    try { Assert-IsolationFirewall } catch { $errors.Add($_.Exception.Message) }
    try {
        $view = Get-IsolationNetworkView
        if ($null -ne $State -and $State.Phase -ne 'Restored') { Assert-IsolationDevices -State $State -View $view }
    } catch { $errors.Add($_.Exception.Message) }
    $ready = $false
    if ($null -ne $view) { $ready = Get-IsolationWifiReady -View $view }
    [pscustomobject]@{ Safe = ($errors.Count -eq 0); WifiReady = $ready; Errors = @($errors.ToArray()); View = $view }
}

function Wait-IsolationVerification {
    param($State, [int]$TimeoutSeconds = 15)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $consecutive = 0
    do {
        $result = Get-IsolationVerification -State $State
        if ($result.Safe) { $consecutive++ } else { $consecutive = 0 }
        if ($consecutive -ge 2) { return $result }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 800
    } while ($true)
    return $result
}

function Invoke-IsolationDisable {
    $state = Read-IsolationState
    $adapters = @(Get-IsolationAdapters)
    if (@($adapters | Where-Object { Test-IsolationWifiAdapter $_ }).Count -eq 0) {
        throw '没有可靠识别到实体无线网卡，未开始切换。'
    }
    if ($null -eq $state -or $state.Phase -eq 'Restored') {
        $state = [pscustomobject]@{
            Version = 1; MachineId = Get-IsolationMachineId; Phase = 'Disabling'
            CreatedAt = [DateTime]::UtcNow.ToString('o'); UpdatedAt = ''; Targets = @()
        }
    }
    $targets = @($state.Targets)
    foreach ($adapter in @(Get-IsolationPhysicalTargets -Adapters $adapters)) {
        if ($adapter.PnPDeviceID -notin @($targets | ForEach-Object PnpId)) { $targets += New-IsolationTarget $adapter }
    }
    if ($targets.Count -eq 0) { throw '未发现实体有线设备，未修改系统。' }
    $state.Targets = $targets
    $state.Phase = 'Disabling'
    # A durable recovery snapshot is required BEFORE the first network mutation.
    Save-IsolationState -State $state
    Write-IsolationLog '开始隔离。已保存原始设备状态。'
    $failures = New-Object 'System.Collections.Generic.List[string]'
    try {
        Ensure-IsolationFirewall
        Assert-IsolationFirewall
    } catch { $failures.Add('防火墙：' + $_.Exception.Message) }
    foreach ($target in @($state.Targets)) {
        try { Disable-IsolationTarget -Target $target }
        catch { $failures.Add($target.Name + '：' + $_.Exception.Message) }
    }
    $result = Wait-IsolationVerification -State $state
    if (-not $result.Safe) {
        $state.Phase = 'Faulted'
        try { Save-IsolationState $state } catch { $failures.Add('状态保存：' + $_.Exception.Message) }
        foreach ($errorMessage in @($result.Errors)) { $failures.Add($errorMessage) }
        Write-IsolationLog ('隔离核验失败；未自动恢复任何有线设备。' + ($failures -join ' | '))
        throw ('隔离核验失败。已保留阻断及禁用措施，不能据此进行风险操作。' + [Environment]::NewLine + ($failures -join [Environment]::NewLine))
    }
    $state.Phase = 'Isolated'
    Save-IsolationState $state
    Write-IsolationLog ('隔离核验通过。WifiReady=' + $result.WifiReady)
    return $result
}

function Restore-IsolationTarget {
    param($Target)
    $null = Find-IsolationAdapter -Adapters @(Get-IsolationAdapters) -Target $Target
    $code = Get-IsolationPnpCode -PnpId $Target.PnpId
    if ($Target.OriginalPnpCode -eq 22) {
        # A device originally disabled by the user must remain disabled.
        if ($code -ne 22) { Disable-IsolationTarget $Target }
        return
    }
    if ($code -eq 22) { Enable-PnpDevice -InstanceId $Target.PnpId -Confirm:$false -ErrorAction Stop }
    elseif ($code -ne 0) { throw ('设备有异常，无法恢复：' + $Target.Name) }
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    $adapter = $null
    do {
        $adapter = Find-IsolationAdapter -Adapters @(Get-IsolationAdapters) -Target $Target
        if ($null -ne $adapter) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $adapter) { throw ('恢复设备后未出现对应网卡：' + $Target.Name) }
    if ($Target.OriginalAdminStatus -eq 1) { $adapter | Enable-NetAdapter -Confirm:$false -ErrorAction Stop }
    else { $adapter | Disable-NetAdapter -Confirm:$false -ErrorAction Stop }
}

function Assert-IsolationRestoredDevices {
    param($State)
    $adapters = @(Get-IsolationAdapters)
    foreach ($target in @($State.Targets)) {
        $code = Get-IsolationPnpCode $target.PnpId
        if ($target.OriginalPnpCode -eq 22) {
            if ($code -ne 22) { throw ('原本禁用的设备未保持禁用：' + $target.Name) }
            continue
        }
        $adapter = Find-IsolationAdapter -Adapters $adapters -Target $target
        if ($code -ne 0 -or $null -eq $adapter -or [int]$adapter.InterfaceAdminStatus -ne $target.OriginalAdminStatus) {
            throw ('未恢复到原始设备状态：' + $target.Name)
        }
    }
}

function Remove-IsolationFirewall {
    $existing = @(Get-IsolationRules -Store PersistentStore)
    foreach ($rule in $existing) {
        if ($rule.Group -ne $script:RuleGroup) { throw '发现同名但非本工具的规则，拒绝删除。' }
        Remove-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -ErrorAction Stop
    }
    if (@(Get-IsolationRules -Store PersistentStore).Count -gt 0 -or @(Get-IsolationRules -Store ActiveStore).Count -gt 0) {
        throw '隔离规则未完全移除。'
    }
}

function Invoke-IsolationRestore {
    $state = Read-IsolationState
    if ($null -eq $state) { throw '没有原始状态记录，无法自动恢复。请不要删除 runtime 文件夹。' }
    if ($state.Phase -eq 'Restored') {
        if (@(Get-IsolationRules -Store PersistentStore).Count -gt 0 -or @(Get-IsolationRules -Store ActiveStore).Count -gt 0) {
            throw '记录为已恢复，但仍存在隔离规则。请先执行禁用再恢复，重新建立一致状态。'
        }
        return
    }
    $state.Phase = 'Restoring'
    Save-IsolationState $state
    Write-IsolationLog '开始恢复有线。'
    try {
        # Keep both blockers until ALL devices have been restored and verified.
        Ensure-IsolationFirewall
        Assert-IsolationFirewall
        foreach ($target in @($state.Targets)) { Restore-IsolationTarget $target }
        Assert-IsolationRestoredDevices $state
        Remove-IsolationFirewall
        $state.Phase = 'Restored'
        Save-IsolationState $state
    } catch {
        $initialError = $_.Exception.Message
        $rollbackErrors = New-Object 'System.Collections.Generic.List[string]'
        try { Ensure-IsolationFirewall } catch { $rollbackErrors.Add('重建阻断：' + $_.Exception.Message) }
        foreach ($target in @($state.Targets)) {
            try { Disable-IsolationTarget $target } catch { $rollbackErrors.Add('重新禁用：' + $target.Name + ' / ' + $_.Exception.Message) }
        }
        $state.Phase = 'Faulted'
        try { Save-IsolationState $state } catch { $rollbackErrors.Add('保存状态：' + $_.Exception.Message) }
        Write-IsolationLog ('恢复失败：' + $initialError + ' | ' + ($rollbackErrors -join ' | '))
        throw ('恢复失败，已尝试重新阻断并禁用有线。请执行检查确认实际状态。' + [Environment]::NewLine + $initialError + [Environment]::NewLine + ($rollbackErrors -join [Environment]::NewLine))
    }
    Write-IsolationLog '恢复成功，原始设备状态已核验，仅本工具的两条规则已移除。'
}

function Show-IsolationVerification {
    param($Result)
    if ($Result.Safe) {
        Write-Host '【隔离核验通过】当前识别的实体有线设备已禁用，有线阻断规则已生效。' -ForegroundColor Green
        if ($Result.WifiReady) {
            Write-Host '无线接口已连接并有默认路由。是否能访问互联网取决于无线网络及代理。'
        } else {
            Write-Host '【当前可能离线】无线接口未就绪；保持有线禁用，请自行连接 Wi-Fi。' -ForegroundColor Yellow
        }
        Write-Host '这是本次检查时的状态；新增硬件、驱动/系统/管理员改动后，请重新禁用并检查。'
    } else {
        Write-Host '【未确认隔离】不要据此进行需要有线隔离的操作。' -ForegroundColor Red
        foreach ($message in @($Result.Errors)) { Write-Host ('  ' + $message) -ForegroundColor Yellow }
    }
    if ($null -ne $Result.View) {
        Write-Host ''
        $Result.View.Adapters | Where-Object HardwareInterface |
            Select-Object Name, InterfaceDescription, Status, InterfaceAdminStatus |
            Format-Table -AutoSize | Out-Host
        Write-Host '当前默认路由（隧道/代理可能显示为 Meta 等虚拟接口）：'
        $Result.View.Routes | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } |
            Select-Object InterfaceAlias, DestinationPrefix, NextHop | Format-Table -AutoSize | Out-Host
    }
}
