function Get-IRPersistenceInfo {
    <#
    .SYNOPSIS
        Read-only inspection of services, scheduled tasks, startup entries, Run/RunOnce keys and WMI event subscriptions.
    .DESCRIPTION
        All discovered commands are parsed as text; nothing is executed. For each item the referenced executable is
        extracted, checked for existence, hashed, and (optionally) Authenticode-checked. Quoting problems (unquoted
        service paths) are flagged as facts about the string, not as verdicts.
    .PARAMETER Config
        Configuration hashtable. Defaults to the built-in configuration.
    .PARAMETER SkipSignature
        Skip Authenticode checks (faster).
    .OUTPUTS
        PSCustomObject collector result.
    .NOTES
        Permissions: tasks of other users and some WMI namespaces need elevation (reported as permission_denied).
    .EXAMPLE
        (Get-IRPersistenceInfo).Records | Group-Object kind
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([System.Collections.IDictionary]$Config, [switch]$SkipSignature)
    if (-not $Config) { $Config = Get-IRConfiguration }
    $redactor = New-IRRedactor -Patterns (@($Config.redaction.patterns) + @($Config.redaction.extraPatterns)) -Enabled $Config.redaction.enabled
    $res = New-IRCollectorResult -Name 'persistence'
    $sigBudget = [int]$Config.limits.maxSignatureChecks
    $sigCache = @{}; $hashCache = @{}

    $enrich = {
        param([System.Collections.IDictionary]$rec, [string]$commandLine)
        $exe = Get-IRCommandLineExecutable $commandLine
        $rec['exec_binary'] = $exe
        $expanded = if ($exe) { [Environment]::ExpandEnvironmentVariables($exe) } else { $null }
        $rec['exec_expanded'] = $expanded
        $isPath = $expanded -and ($expanded -match '^[A-Za-z]:\\|^\\\\')
        $rec['exec_exists'] = if ($isPath) { Test-IRPathExists -Path $expanded } else { $null }
        if ($rec['exec_exists']) {
            $key = $expanded.ToLowerInvariant()
            if (-not $hashCache.ContainsKey($key)) {
                try { $hashCache[$key] = Get-IRRawFileHash -Path $expanded -MaxBytes ([long]$Config.limits.maxHashBytes) } catch { $hashCache[$key] = $null }
            }
            $rec['exec_sha256'] = $hashCache[$key]
            if (-not $SkipSignature -and $sigCache.Count -lt $sigBudget -and -not $sigCache.ContainsKey($key)) {
                try { $sigCache[$key] = Get-IRRawSignature -Path $expanded } catch { $sigCache[$key] = $null }
            }
            if ($sigCache.ContainsKey($key) -and $sigCache[$key]) { $rec['signature_status'] = $sigCache[$key].Status; $rec['signer'] = $sigCache[$key].SignerSubject }
        }
        $rec['command'] = Protect-IRText -Text $commandLine -Redactor $redactor
    }

    # Services
    try {
        foreach ($s in @(Get-IRRawService)) {
            $rec = [ordered]@{ kind = 'service'; name = $s.Name; display_name = $s.DisplayName; start_mode = $s.StartMode; state = $s.State; run_as = $s.StartName }
            $path = "$($s.PathName)"
            & $enrich $rec $path
            $rec['unquoted_path_with_spaces'] = Test-IRUnquotedServicePath $path
            $res.Records.Add([pscustomobject]$rec)
        }
        $res.Sources.Add('Win32_Service')
    }
    catch { Add-IRCaughtError $res 'Win32_Service' $_ }

    # Scheduled tasks
    try {
        foreach ($t in @(Get-IRRawScheduledTask)) {
            $actions = @($t.Actions)
            if ($actions.Count -eq 0) { $actions = @([pscustomobject]@{ Execute = $null; Arguments = $null; WorkingDirectory = $null }) }
            $i = 0
            foreach ($a in $actions) {
                $cmd = (("$($a.Execute) $($a.Arguments)").Trim())
                $rec = [ordered]@{
                    kind = 'scheduled_task'; name = $t.TaskName; task_path = $t.TaskPath; state = $t.State; author = $t.Author; run_as = $t.UserId
                    run_level = $t.RunLevel; hidden = [bool]$t.Hidden; action_index = $i
                    last_run = ConvertTo-IRUtcIso $t.LastRunTime; next_run = ConvertTo-IRUtcIso $t.NextRunTime
                }
                & $enrich $rec $cmd
                if ($a.Execute) { $rec['exec_binary'] = ([string]$a.Execute).Trim('"') }   # Execute is already a bare path
                $res.Records.Add([pscustomobject]$rec)
                $i++
            }
        }
        $res.Sources.Add('Get-ScheduledTask')
    }
    catch { Add-IRCaughtError $res 'Get-ScheduledTask' $_ }

    # Run / RunOnce
    try {
        foreach ($r in @(Get-IRRawRegistryRunValue)) {
            $rec = [ordered]@{ kind = 'run_key'; registry_key = $r.Key; name = $r.Name }
            & $enrich $rec "$($r.Value)"
            $res.Records.Add([pscustomobject]$rec)
        }
        $res.Sources.Add('registry:Run/RunOnce')
    }
    catch { Add-IRCaughtError $res 'registry:Run/RunOnce' $_ }

    # Startup commands (WMI) and startup folders
    try {
        foreach ($s in @(Get-IRRawStartupCommand)) {
            $rec = [ordered]@{ kind = 'startup_command'; name = $s.Name; location = $s.Location; user = $s.User }
            & $enrich $rec "$($s.Command)"
            $res.Records.Add([pscustomobject]$rec)
        }
        $res.Sources.Add('Win32_StartupCommand')
    }
    catch { Add-IRCaughtError $res 'Win32_StartupCommand' $_ }
    try {
        foreach ($f in @(Get-IRRawStartupFolderItem)) {
            $rec = [ordered]@{ kind = 'startup_folder_item'; name = $f.Name; folder = $f.Folder; path = $f.FullName; size = $f.Length; modified = ConvertTo-IRUtcIso $f.LastWriteTimeUtc }
            if ($f.FullName) {
                try { $rec['sha256'] = Get-IRRawFileHash -Path $f.FullName -MaxBytes ([long]$Config.limits.maxHashBytes) } catch { $rec['sha256'] = $null }
            }
            $res.Records.Add([pscustomobject]$rec)
        }
        $res.Sources.Add('startup folders')
    }
    catch { Add-IRCaughtError $res 'startup folders' $_ }

    # Winlogon values (read-only registry queries)
    foreach ($name in @('Shell', 'Userinit')) {
        try {
            $v = Get-IRRawRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name $name
            $res.Records.Add([pscustomobject][ordered]@{ kind = 'winlogon_value'; name = $name; value = "$v" })
        }
        catch { Add-IRCaughtError $res "registry:Winlogon\$name" $_ }
    }

    # WMI event subscriptions
    try {
        foreach ($w in @(Get-IRRawWmiSubscription)) {
            $rec = [ordered]@{ kind = 'wmi_subscription'; subscription_part = $w.Kind; name = $w.Name; consumer_type = $w.ConsumerType; filter = $w.Filter; consumer = $w.Consumer }
            $rec['query'] = Protect-IRText -Text "$($w.Query)" -Redactor $redactor
            $rec['command'] = Protect-IRText -Text "$($w.Command)" -Redactor $redactor
            $rec['has_script_text'] = -not [string]::IsNullOrEmpty($w.ScriptText)
            $res.Records.Add([pscustomobject]$rec)
        }
        $res.Sources.Add('root\subscription')
    }
    catch { Add-IRCaughtError $res 'root\subscription' $_ }
    $res.Notes.Add('Not covered: COM hijacking, AppInit/AppCert DLLs, IFEO debuggers, LSA/authentication packages, drivers, BITS jobs, browser extensions, DLL search-order issues.')
    return (Complete-IRCollectorResult $res)
}
