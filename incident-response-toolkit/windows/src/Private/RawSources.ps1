# Thin wrappers around Windows data sources. Collectors call ONLY these functions, which:
#   * are read-only (Get-*/Test-* cmdlets and CIM queries; no Set-/Remove-/Invoke-CimMethod that changes state),
#   * return plain objects with a documented, platform-independent shape,
#   * can be replaced by test doubles (see tests/Shim and tests/Unit) so the collector logic is testable anywhere.
# Errors are NOT swallowed here: collectors classify them (permission_denied, unavailable, ...).

$script:RunKeyPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)

function Get-IRRawOperatingSystem {
    [CmdletBinding()] param()
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $tz = Get-CimInstance -ClassName Win32_TimeZone -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Caption = $os.Caption; Version = $os.Version; BuildNumber = $os.BuildNumber; Architecture = $os.OSArchitecture
        LastBootUpTime = $os.LastBootUpTime; LocalDateTime = $os.LocalDateTime
        TimeZone = if ($tz) { $tz.Caption } else { $null }; TimeZoneOffsetMinutes = if ($tz) { $tz.Bias * -1 } else { $null }
        ProductType = $os.ProductType
    }
}

function Get-IRRawComputerSystem {
    [CmdletBinding()] param()
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    [pscustomobject]@{ Name = $cs.Name; Domain = $cs.Domain; PartOfDomain = $cs.PartOfDomain; Manufacturer = $cs.Manufacturer; Model = $cs.Model }
}

function Get-IRRawSecurityProduct {
    [CmdletBinding()] param()
    # SecurityCenter2 exists on client SKUs only; servers raise "Invalid namespace" (classified as unavailable).
    Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{ Name = $_.displayName; ProductState = $_.productState; Path = $_.pathToSignedProductExe } }
}

function Get-IRRawDefender {
    [CmdletBinding()] param()
    $s = Get-MpComputerStatus -ErrorAction Stop
    [pscustomobject]@{
        AMServiceEnabled = $s.AMServiceEnabled; AntivirusEnabled = $s.AntivirusEnabled; RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
        AntivirusSignatureLastUpdated = $s.AntivirusSignatureLastUpdated; IsTamperProtected = $s.IsTamperProtected
    }
}

function Get-IRRawFirewallProfile {
    [CmdletBinding()] param()
    Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Enabled = "$($_.Enabled)" -eq 'True' } }
}

function Get-IRRawRegistryValue {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
}

function Get-IRRawProcess {
    [CmdletBinding()] param()
    Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            ProcessId = [int]$_.ProcessId; ParentProcessId = [int]$_.ParentProcessId; Name = $_.Name; ExecutablePath = $_.ExecutablePath
            CommandLine = $_.CommandLine; CreationDate = $_.CreationDate; SessionId = $_.SessionId
        }
    }
}

function Get-IRRawProcessOwner {
    [CmdletBinding()] param([Parameter(Mandatory)][int]$ProcessId)
    # GetOwner is a read-only CIM method (it queries the process token owner).
    $p = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
    if ($null -eq $p) { return $null }
    $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
    if ($o.ReturnValue -ne 0) { return $null }
    [pscustomobject]@{ User = $o.User; Domain = $o.Domain }
}

function Get-IRRawSignature {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    [pscustomobject]@{
        Status = "$($s.Status)"; SignerSubject = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }
        SignerThumbprint = if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint } else { $null }
    }
}

function Get-IRRawTcpConnection {
    [CmdletBinding()] param()
    Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ State = "$($_.State)"; LocalAddress = "$($_.LocalAddress)"; LocalPort = [int]$_.LocalPort
            RemoteAddress = "$($_.RemoteAddress)"; RemotePort = [int]$_.RemotePort; OwningProcess = [int]$_.OwningProcess }
    }
}

function Get-IRRawUdpEndpoint {
    [CmdletBinding()] param()
    Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ LocalAddress = "$($_.LocalAddress)"; LocalPort = [int]$_.LocalPort; OwningProcess = [int]$_.OwningProcess }
    }
}

function Get-IRRawLocalUser {
    [CmdletBinding()] param()
    Get-LocalUser -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Enabled = [bool]$_.Enabled; LastLogon = $_.LastLogon; PasswordLastSet = $_.PasswordLastSet
            PasswordRequired = [bool]$_.PasswordRequired; SID = "$($_.SID)" }
    }
}

function Get-IRRawLocalGroupMember {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Group)
    Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Name = "$($_.Name)"; ObjectClass = "$($_.ObjectClass)"; SID = "$($_.SID)" }
    }
}

function Get-IRRawLogonSession {
    [CmdletBinding()] param()
    $sessions = Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop
    $links = Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction SilentlyContinue
    foreach ($s in $sessions) {
        $who = $null
        foreach ($l in @($links)) { if ($l.Dependent.LogonId -eq $s.LogonId) { $who = $l.Antecedent; break } }
        [pscustomobject]@{ LogonId = "$($s.LogonId)"; LogonType = [int]$s.LogonType; StartTime = $s.StartTime
            AuthenticationPackage = $s.AuthenticationPackage; User = if ($who) { $who.Name } else { $null }; Domain = if ($who) { $who.Domain } else { $null } }
    }
}

function Get-IRRawScheduledTask {
    [CmdletBinding()] param()
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $info = $null
        try { $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction Stop } catch { $info = $null }
        [pscustomobject]@{
            TaskName = $_.TaskName; TaskPath = $_.TaskPath; State = "$($_.State)"; Author = $_.Author
            UserId = if ($_.Principal) { $_.Principal.UserId } else { $null }; RunLevel = if ($_.Principal) { "$($_.Principal.RunLevel)" } else { $null }
            Hidden = if ($_.Settings) { [bool]$_.Settings.Hidden } else { $false }
            LastRunTime = if ($info) { $info.LastRunTime } else { $null }; NextRunTime = if ($info) { $info.NextRunTime } else { $null }
            Actions = @($_.Actions | ForEach-Object { [pscustomobject]@{ Execute = $_.Execute; Arguments = $_.Arguments; WorkingDirectory = $_.WorkingDirectory } })
        }
    }
}

function Get-IRRawService {
    [CmdletBinding()] param()
    Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; PathName = $_.PathName; StartMode = $_.StartMode; State = $_.State; StartName = $_.StartName }
    }
}

function Get-IRRawStartupCommand {
    [CmdletBinding()] param()
    Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Command = $_.Command; Location = $_.Location; User = $_.User }
    }
}

function Get-IRRawRegistryRunValue {
    [CmdletBinding()] param()
    foreach ($key in $script:RunKeyPaths) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            [pscustomobject]@{ Key = $key; Name = $p.Name; Value = "$($p.Value)" }
        }
    }
}

function Get-IRRawWmiSubscription {
    [CmdletBinding()] param()
    $ns = 'root\subscription'
    foreach ($f in @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop)) {
        [pscustomobject]@{ Kind = 'Filter'; Name = $f.Name; Query = $f.Query; ConsumerType = $null; Command = $null; ScriptText = $null; Filter = $null; Consumer = $null }
    }
    foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{ Kind = 'Consumer'; Name = $c.Name; Query = $null; ConsumerType = 'CommandLineEventConsumer'; Command = $c.CommandLineTemplate; ScriptText = $null; Filter = $null; Consumer = $null }
    }
    foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{ Kind = 'Consumer'; Name = $c.Name; Query = $null; ConsumerType = 'ActiveScriptEventConsumer'; Command = $null; ScriptText = $c.ScriptText; Filter = $null; Consumer = $null }
    }
    foreach ($b in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{ Kind = 'Binding'; Name = $null; Query = $null; ConsumerType = $null; Command = $null; ScriptText = $null; Filter = "$($b.Filter)"; Consumer = "$($b.Consumer)" }
    }
}

function Get-IRRawWinEvent {
    <#
    Returns normalised events: TimeCreatedUtc, Id, ProviderName, LogName, MachineName, RecordId, Level, Data (hashtable).
    Throws on missing log / access denied; "no events" is returned as an empty result.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LogName, [int[]]$Id, [Parameter(Mandatory)][datetime]$Since, [int]$MaxEvents = 1000)
    $filter = @{ LogName = $LogName; StartTime = $Since }
    if ($Id -and $Id.Count -gt 0) { $filter['Id'] = $Id }
    try { $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') { return }
        throw
    }
    foreach ($e in $events) {
        $data = @{}
        try {
            $xml = [xml]$e.ToXml()
            foreach ($d in @($xml.Event.EventData.Data)) { if ($d -and $d.Name) { $data[$d.Name] = "$($d.'#text')" } }
        }
        catch { $data['_parse_error'] = 'event xml could not be parsed' }
        [pscustomobject]@{ TimeCreatedUtc = $e.TimeCreated.ToUniversalTime(); Id = [int]$e.Id; ProviderName = $e.ProviderName; LogName = $e.LogName
            MachineName = $e.MachineName; RecordId = $e.RecordId; Level = $e.LevelDisplayName; Data = $data }
    }
}

function Test-IRPathExists {
    [CmdletBinding()] [OutputType([bool])] param([Parameter(Mandatory)][string]$Path)
    return (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)
}

function Get-IRRawFileMetadata {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $i = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    [pscustomobject]@{ FullName = $i.FullName; Length = if ($i.PSIsContainer) { 0 } else { $i.Length }; LastWriteTimeUtc = $i.LastWriteTimeUtc; Attributes = "$($i.Attributes)" }
}

function Get-IRRawStartupFolderItem {
    [CmdletBinding()] param()
    $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
    foreach ($d in $dirs) {
        if ($d -and (Test-Path -LiteralPath $d)) {
            Get-ChildItem -LiteralPath $d -Force -File -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Folder = $d; Name = $_.Name; FullName = $_.FullName; Length = $_.Length; LastWriteTimeUtc = $_.LastWriteTimeUtc } }
        }
    }
}

function Get-IRRawFileHash {
    # Hashing of discovered executables goes through this wrapper so tests can substitute it without touching evidence hashing.
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [long]$MaxBytes = 0)
    Get-IRFileSha256 -Path $Path -MaxBytes $MaxBytes
}
