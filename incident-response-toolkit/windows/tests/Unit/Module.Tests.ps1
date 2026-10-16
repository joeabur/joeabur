BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
    $script:ManifestPath = Join-Path $script:Root 'src\Modules\WinIRToolkit\WinIRToolkit.psd1'
    Import-Module $script:ManifestPath -Force
    $script:Commands = @(Get-Command -Module WinIRToolkit)
}

Describe 'Module manifest' {
    It 'is a valid module manifest' {
        { Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop } | Should -Not -Throw
    }
    It 'declares Windows PowerShell 5.1 as the minimum version' {
        (Import-PowerShellDataFile $script:ManifestPath).PowerShellVersion | Should -Be '5.1'
    }
    It 'exports exactly the documented public commands' {
        $declared = @((Import-PowerShellDataFile $script:ManifestPath).FunctionsToExport)
        foreach ($c in $script:Commands) { $declared | Should -Contain $c.Name }
        $script:Commands.Count | Should -Be $declared.Count
    }
}

Describe 'Public commands' {
    It 'use approved verbs' {
        $approved = (Get-Verb).Verb
        foreach ($c in $script:Commands) { $approved | Should -Contain $c.Verb }
    }
    It 'have comment-based help with a synopsis and an example' {
        foreach ($c in $script:Commands) {
            $h = Get-Help -Name $c.Name -Full
            ("$($h.Synopsis)").Trim() | Should -Not -BeNullOrEmpty
            @($h.examples.example).Count | Should -BeGreaterThan 0
        }
    }
    It 'do not expose private helpers' {
        (Get-Command -Module WinIRToolkit -Name 'Get-IRRawProcess' -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
    }
}

Describe 'Source hygiene' {
    It 'contains no commands that change system state or run discovered content' {
        $forbidden = 'Stop-Process', 'Remove-Item', 'Set-ItemProperty', 'New-ItemProperty', 'Disable-', 'Enable-', 'Stop-Service', 'Set-Service', 'Start-Process', 'Invoke-Expression', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Send-MailMessage', 'Unregister-', 'Set-MpPreference', 'Add-MpPreference'
        $files = Get-ChildItem (Join-Path $script:Root 'src') -Recurse -Filter '*.ps1'
        foreach ($f in $files) {
            $text = Get-Content -LiteralPath $f.FullName -Raw
            $code = ($text -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            foreach ($bad in $forbidden) {
                $pattern = '(?i)(?<![\w-])' + [regex]::Escape($bad) + '(?![\w])'
                if ($bad.EndsWith('-')) { $pattern = '(?i)(?<![\w-])' + [regex]::Escape($bad) + '\w+' }
                ($code -match $pattern) | Should -BeFalse -Because "$($f.Name) must not use $bad"
            }
        }
    }
}
