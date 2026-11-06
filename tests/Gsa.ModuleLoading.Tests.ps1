#Requires -Version 7.6
BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    $fixture = Join-Path $PSScriptRoot 'helpers/Invoke-GsaModuleLoadingFixture.ps1'
}
Describe 'Real module dependency loading' {
    It 'runs the safe postprovision hook without cloud calls in a fresh process' {
        $output = & (Get-Process -Id $PID).Path -NoProfile -File $fixture -Root $root -Mode PostProvision 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output | Out-String)
        @((($output | Out-String | ConvertFrom-Json).PSObject.Properties)).Count | Should -Be 0
    }
    It 'keeps shared dependency exports available across the full module graph' {
        $output = & (Get-Process -Id $PID).Path -NoProfile -File $fixture -Root $root -Mode ModuleGraph 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output | Out-String)
        $output | Should -Contain 'Module exports remain available.'
    }
}
