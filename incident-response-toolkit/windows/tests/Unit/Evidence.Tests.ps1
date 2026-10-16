BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    Import-Module (Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1') -Force
    . (Join-Path $script:Root 'tests\Fixtures\FakeWindows.ps1')
    $script:Module = Get-Module WinIRToolkit
    $script:Case = Join-Path $script:Root 'sample-data\case-001'
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("wir-ev-" + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    $null = New-Item -ItemType Directory $script:Tmp
    function script:Copy-Case($name) { $d = Join-Path $script:Tmp $name; Copy-Item -Recurse $script:Case $d; $d }
    function script:InModule([scriptblock]$Block, [object[]]$ArgumentList) { & $script:Module $Block @ArgumentList }
}

Describe 'Collection workflow (synthetic sources)' {
    It 'writes unique evidence directories, artifacts and a verifiable manifest' {
        Install-IRFakeSource -Module $script:Module
        $r = Invoke-IRCollection -Profile BasicTriage -OutputPath (Join-Path $script:Tmp 'out') -AllowNonWindows
        $r2 = Invoke-IRCollection -Profile BasicTriage -OutputPath (Join-Path $script:Tmp 'out') -AllowNonWindows
        $r.EvidenceDir | Should -Not -Be $r2.EvidenceDir
        (Join-Path $r.EvidenceDir 'manifest.json') | Should -Exist
        foreach ($n in 'inventory', 'processes', 'network', 'accounts', 'persistence', 'events') { (Join-Path $r.EvidenceDir "artifacts\$n.json") | Should -Exist }
        $v = Test-IREvidenceManifest -Path $r.EvidenceDir
        $v.Ok | Should -BeTrue
        $v.ManifestSha256 | Should -Be $r.ManifestSha256
        $r.Manifest.tool.name | Should -Be 'windows-ir-toolkit'
        $r.Manifest.started_at | Should -Match 'Z$'
        ($r.Manifest.limitations -join ' ') | Should -Match 'not independently tamper-proof'
    }
    It 'previews with -DryRun without creating anything' {
        $out = Join-Path $script:Tmp 'dry'
        $r = Invoke-IRCollection -Profile FocusedIncident -OutputPath $out -DryRun
        $r.DryRun | Should -BeTrue
        @($r.Plan).Count | Should -Be 6
        $out | Should -Not -Exist
    }
    It 'lets one failing collector not stop the others' {
        Install-IRFakeSource -Module $script:Module
        Set-IRFakeOverride -Module $script:Module -Name 'Get-IRRawService' -Body { throw 'boom' }
        $r = Invoke-IRCollection -Profile PersistenceReview -OutputPath (Join-Path $script:Tmp 'partial') -AllowNonWindows
        $st = @{}; foreach ($a in $r.Manifest.artifacts) { $st[$a.name] = $a.status }
        $st['persistence'] | Should -Be 'partial'
        $st['inventory'] | Should -Be 'ok'
        $st['events'] | Should -Be 'skipped'
        Install-IRFakeSource -Module $script:Module
    }
    It 'refuses live collection on non-Windows hosts unless explicitly allowed' {
        if (-not (script:InModule { Test-IRWindowsHost })) { { Invoke-IRCollection -Profile BasicTriage -OutputPath (Join-Path $script:Tmp 'nowin') } | Should -Throw 'only supported on Windows' }
    }
    It 'validates profile, collectors, window and configuration' {
        { Invoke-IRCollection -Profile Nope -OutputPath (Join-Path $script:Tmp 'x') -DryRun } | Should -Throw 'Unknown profile'
        { Invoke-IRCollection -Profile BasicTriage -Collector bogus -OutputPath (Join-Path $script:Tmp 'x') -DryRun } | Should -Throw 'Unknown collector'
        { Invoke-IRCollection -Profile BasicTriage -EventHours 99999 -OutputPath (Join-Path $script:Tmp 'x') -DryRun } | Should -Throw
        { Invoke-IRCollection -Profile BasicTriage -ConfigPath (Join-Path $script:Tmp 'missing.json') -OutputPath (Join-Path $script:Tmp 'x') -DryRun } | Should -Throw
    }
}

Describe 'Output path validation' {
    It 'rejects empty, traversal and file paths' {
        { script:InModule { Resolve-IROutputPath -Path '' } } | Should -Throw
        { script:InModule { Resolve-IROutputPath -Path 'a\..\b' } } | Should -Throw '..'
        $f = Join-Path $script:Tmp 'afile.txt'; Set-Content $f 'x'
        { script:InModule { param($f) Resolve-IROutputPath -Path $f } @($f) } | Should -Throw 'existing file'
    }
    It 'rejects device paths' { { script:InModule { Resolve-IROutputPath -Path '\\.\C:\evidence' } } | Should -Throw 'Device' }
    It 'refuses unsafe relative paths when joining' {
        foreach ($rel in '..\x', 'a\..\..\x', '\abs', 'C:\abs', '') { { script:InModule { param($b, $r) Join-IRSafePath -Base $b -Relative $r } @($script:Tmp, $rel) } | Should -Throw }
        script:InModule { param($b) Join-IRSafePath -Base $b -Relative 'artifacts/x.json' } @($script:Tmp) | Should -Match 'x\.json$'
    }
    It 'never overwrites an existing file' {
        $f = Join-Path $script:Tmp 'once.txt'
        script:InModule { param($f) Write-IRFileExclusive -Path $f -Text 'one' } @($f)
        { script:InModule { param($f) Write-IRFileExclusive -Path $f -Text 'two' } @($f) } | Should -Throw 'overwrite'
        (Get-Content $f -Raw).Trim() | Should -Be 'one'
    }
}

Describe 'Manifest verification' {
    It 'passes for the committed synthetic evidence' {
        (Test-IREvidenceManifest -Path $script:Case).Ok | Should -BeTrue
        (Test-IREvidenceManifest -Path (Join-Path $script:Root 'sample-data\baseline')).Ok | Should -BeTrue
    }
    It 'detects modified, missing and unexpected files' {
        $d = script:Copy-Case 'tamper'
        Add-Content (Join-Path $d 'artifacts\network.json') ' '
        Remove-Item (Join-Path $d 'artifacts\accounts.json')
        Set-Content (Join-Path $d 'artifacts\extra.json') '{}'
        $v = Test-IREvidenceManifest -Path $d
        $v.Ok | Should -BeFalse
        @($v.Modified).Count | Should -Be 1
        $v.Missing | Should -Contain 'artifacts/accounts.json'
        $v.Unexpected | Should -Contain 'artifacts/extra.json'
    }
    It 'rejects traversal entries and invalid manifests' {
        $d = script:Copy-Case 'trav'
        $m = Get-Content (Join-Path $d 'manifest.json') -Raw | ConvertFrom-Json
        $m.files += [pscustomobject]@{ path = '..\..\Windows\win.ini'; size = 1; sha256 = ('0' * 64) }
        Set-Content (Join-Path $d 'manifest.json') ($m | ConvertTo-Json -Depth 8)
        @((Test-IREvidenceManifest -Path $d).Unsafe).Count | Should -BeGreaterThan 0
        Set-Content (Join-Path $d 'manifest.json') '{ broken'
        (Test-IREvidenceManifest -Path $d).Error | Should -Match 'not valid JSON'
        Remove-Item (Join-Path $d 'manifest.json')
        (Test-IREvidenceManifest -Path $d).Error | Should -Match 'not found'
        (Test-IREvidenceManifest -Path (Join-Path $script:Tmp 'nope')).Error | Should -Match 'not found'
    }
    It 'refuses to analyse tampered evidence unless -AllowUnverified is given' {
        $d = script:Copy-Case 'blocked'
        Add-Content (Join-Path $d 'artifacts\network.json') ' '
        { Invoke-IRAnalysis -Path $d } | Should -Throw 'verification FAILED'
        $a = Invoke-IRAnalysis -Path $d -AllowUnverified
        $a.Verification.Ok | Should -BeFalse
    }
    It 'rejects malformed artifact files' {
        $d = script:Copy-Case 'malformed'
        Set-Content (Join-Path $d 'artifacts\network.json') '{ nope'
        { Invoke-IRAnalysis -Path $d -AllowUnverified } | Should -Throw 'Malformed artifact'
        { Invoke-IRAnalysis -Path $script:Tmp } | Should -Throw
    }
    It 'seals imported evidence and refuses to overwrite a manifest' {
        $d = Join-Path $script:Tmp 'import'; $null = New-Item -ItemType Directory (Join-Path $d 'artifacts') -Force
        Copy-Item (Join-Path $script:Case 'artifacts\network.json') (Join-Path $d 'artifacts')
        $s = Protect-IREvidenceDirectory -Path $d
        $s.Sha256 | Should -Match '^[0-9a-f]{64}$'
        (Test-IREvidenceManifest -Path $d).Ok | Should -BeTrue
        { Protect-IREvidenceDirectory -Path $d } | Should -Throw 'already exists'
    }
    It 'refuses to seal symbolic links' {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            $d = Join-Path $script:Tmp 'linked'; $null = New-Item -ItemType Directory (Join-Path $d 'artifacts') -Force
            Copy-Item (Join-Path $script:Case 'artifacts\network.json') (Join-Path $d 'artifacts\a.json')
            $ok = $true; try { $null = New-Item -ItemType SymbolicLink -Path (Join-Path $d 'artifacts\b.json') -Target (Join-Path $d 'artifacts\a.json') -ErrorAction Stop } catch { $ok = $false }
            if ($ok) { { Protect-IREvidenceDirectory -Path $d } | Should -Throw 'symbolic link' }
        }
    }
}

AfterAll { Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue }
