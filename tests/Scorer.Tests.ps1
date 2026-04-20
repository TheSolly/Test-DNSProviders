#Requires -Modules Pester

# Pester tests for DNS-ML-Scorer.psm1
#
# Run from the repo root with:
#   Invoke-Pester -Path .\tests\Scorer.Tests.ps1 -Output Detailed
#
# These tests are pure-unit (no network) and exercise the scoring math,
# weight handling, profile activation, basis calculation, feature/diversity
# bonuses, Bayesian shrinkage, and stale-data decay.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:ModulePath = Join-Path $RepoRoot 'DNS-ML-Scorer.psd1'
    if (-not (Test-Path $ModulePath)) {
        $script:ModulePath = Join-Path $RepoRoot 'DNS-ML-Scorer.psm1'
    }
    Import-Module $ModulePath -Force -DisableNameChecking
}

Describe 'Initialize-MLData' {
    It 'returns an empty data structure when no persisted file exists' {
        $tmp = [System.IO.Path]::GetTempFileName()
        Remove-Item $tmp -Force
        try {
            $d = Initialize-MLData -DataFile $tmp
            $d                  | Should -Not -BeNull
            $d.ContainsKey('Servers') | Should -BeTrue
            $d.ContainsKey('Pairs')   | Should -BeTrue
            $d.ContainsKey('Weights') | Should -BeTrue
            $d.TotalRuns        | Should -Be 0
            $d.Servers.Count    | Should -Be 0
        } finally {
            if (Test-Path $tmp) { Remove-Item $tmp -Force }
        }
    }
}

Describe 'Weights and profiles' {
    BeforeEach {
        $tmp = [System.IO.Path]::GetTempFileName(); Remove-Item $tmp -Force
        $script:d = Initialize-MLData -DataFile $tmp
    }

    It 'lists the expected profile names' {
        $names = Get-MLProfileNames
        $names | Should -Contain 'Default'
        $names | Should -Contain 'Gaming'
        $names | Should -Contain 'Streaming'
        $names | Should -Contain 'Browsing'
        $names | Should -Contain 'Privacy'
    }

    It 'activates a profile and updates Weights to the profile values' {
        Set-MLProfile -MLData $d -ProfileName 'Gaming' | Out-Null
        $d.ActiveProfile        | Should -Be 'Gaming'
        # Gaming profile is Jitter-heavy
        $d.Weights.Jitter       | Should -BeGreaterThan $d.Weights.SuccessRate
        # Weights always sum to 1 after activation
        $sum = ($d.Weights.Values | Measure-Object -Sum).Sum
        [Math]::Abs($sum - 1.0) | Should -BeLessThan 0.0001
    }

    It 'Set-MLWeights clamps negatives and renormalizes' {
        Set-MLWeights -MLData $d -Weights @{
            ResponseTime = 2.0; Jitter = -1.0; SuccessRate = 1.0;
            HistoricalTrend = 0.5; AdvancedFeatures = 0.5
        } | Out-Null
        $d.Weights.Jitter | Should -Be 0
        $sum = ($d.Weights.Values | Measure-Object -Sum).Sum
        [Math]::Abs($sum - 1.0) | Should -BeLessThan 0.0001
    }
}

Describe 'Get-MLRankingBasis' {
    It 'returns the legacy floor when fewer than MinSamplesForBasis servers exist' {
        $tmp = [System.IO.Path]::GetTempFileName(); Remove-Item $tmp -Force
        $d = Initialize-MLData -DataFile $tmp
        $b = Get-MLRankingBasis -MLData $d
        $b.RTBasis     | Should -BeGreaterOrEqual 50
        $b.JitterBasis | Should -BeGreaterOrEqual 10
    }

    It 'derives a population-relative basis once enough servers exist' {
        $tmp = [System.IO.Path]::GetTempFileName(); Remove-Item $tmp -Force
        $d = Initialize-MLData -DataFile $tmp
        Update-ServerMLData -MLData $d -IP '1.1.1.1' -Provider 'CF'    -ResponseTime 10  -SuccessRate 100 -Jitter 1
        Update-ServerMLData -MLData $d -IP '8.8.8.8' -Provider 'Goog'  -ResponseTime 25  -SuccessRate 100 -Jitter 5
        Update-ServerMLData -MLData $d -IP '9.9.9.9' -Provider 'Quad9' -ResponseTime 60  -SuccessRate 90  -Jitter 20
        Update-ServerMLData -MLData $d -IP '4.2.2.2' -Provider 'L3'    -ResponseTime 250 -SuccessRate 80  -Jitter 60
        $b = Get-MLRankingBasis -MLData $d
        # Basis still respects the minimum floor
        $b.RTBasis     | Should -BeGreaterOrEqual 50
        $b.JitterBasis | Should -BeGreaterOrEqual 10
    }
}

Describe 'Calculate-ServerScore + Get-RankingScore' {
    BeforeEach {
        $tmp = [System.IO.Path]::GetTempFileName(); Remove-Item $tmp -Force
        $script:d = Initialize-MLData -DataFile $tmp
        Update-ServerMLData -MLData $d -IP '1.1.1.1' -Provider 'CF'   -ResponseTime 10 -SuccessRate 100 -Jitter 1 -IPv6Support $true -DNSSECSupport $true
        Update-ServerMLData -MLData $d -IP '8.8.8.8' -Provider 'Goog' -ResponseTime 25 -SuccessRate 95  -Jitter 8 -IPv6Support $true
        Update-ServerMLData -MLData $d -IP '9.9.9.9' -Provider 'Quad' -ResponseTime 60 -SuccessRate 80  -Jitter 25
    }

    It 'ranks the obviously-better server higher than the obviously-worse one' {
        $b = Get-MLRankingBasis -MLData $d
        $rCF   = Get-RankingScore -ServerData $d.Servers['1.1.1.1|CF']   -Weights $d.Weights -Basis $b
        $rQuad = Get-RankingScore -ServerData $d.Servers['9.9.9.9|Quad'] -Weights $d.Weights -Basis $b
        $rCF | Should -BeGreaterThan $rQuad
    }

    It 'Get-RankingScore returns a value within [0,100]' {
        $b = Get-MLRankingBasis -MLData $d
        foreach ($k in $d.Servers.Keys) {
            $v = Get-RankingScore -ServerData $d.Servers[$k] -Weights $d.Weights -Basis $b
            $v | Should -BeGreaterOrEqual 0
            $v | Should -BeLessOrEqual   100
        }
    }
}

Describe 'Bayesian shrinkage' {
    It 'shrinks a single-sample lucky server toward the population' {
        $tmp = [System.IO.Path]::GetTempFileName(); Remove-Item $tmp -Force
        $d = Initialize-MLData -DataFile $tmp

        # Lots of mediocre servers
        for ($i=0; $i -lt 5; $i++) {
            Update-ServerMLData -MLData $d -IP "10.0.0.$i" -Provider "Mediocre$i" -ResponseTime 100 -SuccessRate 80 -Jitter 30
        }
        # Lucky newcomer with one perfect sample
        Update-ServerMLData -MLData $d -IP '7.7.7.7' -Provider 'Lucky' -ResponseTime 1 -SuccessRate 100 -Jitter 0

        $b = Get-MLRankingBasis -MLData $d
        $lucky = $d.Servers['7.7.7.7|Lucky']
        $rank  = Get-RankingScore -ServerData $lucky -Weights $d.Weights -Basis $b

        # With shrinkage, a 1-sample server can't reach 100
        $rank | Should -BeLessThan 100
    }
}

Describe 'Get-PairDiversityBonus' {
    It 'gives full bonus for different provider AND different /24' {
        Get-PairDiversityBonus -PrimaryIP '1.1.1.1' -SecondaryIP '9.9.9.9' `
            -PrimaryProvider 'Cloudflare' -SecondaryProvider 'Quad9' |
            Should -Be 10
    }

    It 'penalizes same-provider pairs' {
        $bonus = Get-PairDiversityBonus -PrimaryIP '8.8.8.8' -SecondaryIP '8.8.4.4' `
            -PrimaryProvider 'Google DNS' -SecondaryProvider 'Google DNS Secondary'
        # Different /24 (8.8.8.x vs 8.8.4.x), same provider root => only +4
        $bonus | Should -Be 4
    }

    It 'gives zero bonus for same provider AND same /24' {
        Get-PairDiversityBonus -PrimaryIP '1.1.1.1' -SecondaryIP '1.1.1.2' `
            -PrimaryProvider 'Cloudflare' -SecondaryProvider 'Cloudflare' |
            Should -Be 0
    }
}

Describe 'Update-ServerMLData clamping' {
    It 'clamps SuccessRate into [0,100]' {
        $tmp = [System.IO.Path]::GetTempFileName(); Remove-Item $tmp -Force
        $d = Initialize-MLData -DataFile $tmp
        Update-ServerMLData -MLData $d -IP '1.2.3.4' -Provider 'X' -ResponseTime 10 -SuccessRate 999 -Jitter 5
        $s = $d.Servers['1.2.3.4|X']
        $avg = $s.TotalSuccessRate / $s.TestCount
        $avg | Should -BeLessOrEqual 100
        $avg | Should -BeGreaterOrEqual 0
    }

    It 'records new capability flags when provided' {
        $tmp = [System.IO.Path]::GetTempFileName(); Remove-Item $tmp -Force
        $d = Initialize-MLData -DataFile $tmp
        Update-ServerMLData -MLData $d -IP '1.2.3.4' -Provider 'X' `
            -ResponseTime 10 -SuccessRate 100 -Jitter 1 `
            -EDNS0Support $true -TCPSupport $true -FilteringSupport $true
        $s = $d.Servers['1.2.3.4|X']
        $s.EDNS0Capable     | Should -BeTrue
        $s.TCPCapable       | Should -BeTrue
        $s.FilteringCapable | Should -BeTrue
    }
}

Describe 'Update-PairMLData diversity integration' {
    It 'records and applies the diversity bonus to the stored score' {
        $tmp = [System.IO.Path]::GetTempFileName(); Remove-Item $tmp -Force
        $d = Initialize-MLData -DataFile $tmp
        Update-PairMLData -MLData $d `
            -PrimaryIP '1.1.1.1' -SecondaryIP '9.9.9.9' `
            -PrimaryProvider 'Cloudflare' -SecondaryProvider 'Quad9' `
            -CombinedScore 50 -ConfigType 'Test'
        $key = '1.1.1.1|9.9.9.9'
        $p = $d.Pairs[$key]
        $p.DiversityBonus | Should -Be 10
        # Stored TotalScore should be reduced by the bonus (50 - 10 = 40)
        $p.TotalScore     | Should -Be 40
    }
}
