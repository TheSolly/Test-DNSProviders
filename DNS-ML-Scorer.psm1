# DNS Machine Learning Scorer
# Tracks and prioritizes "best of the best" DNS configurations
# Created: November 2025

<#
.SYNOPSIS
Machine learning system for DNS performance optimization

.DESCRIPTION
This module implements a scoring algorithm that learns from historical DNS test results
to identify and prioritize the best-performing DNS configurations over time.

The system tracks:
- Individual DNS server performance metrics
- DNS pair configurations (Primary + Secondary)
- Time-of-day performance patterns
- Network condition adaptability
- Long-term reliability trends

.NOTES
The ML model uses a weighted scoring system that improves with more data:
- Response Time (40%)
- Reliability/Success Rate (30%)
- Jitter/Consistency (15%)
- Historical Trend (10%)
- Advanced Features (IPv6, DNSSEC, Quality) (5%)
#>

# Global configuration
$script:MLDataFile = Join-Path $PSScriptRoot "dns-ml-data.json"
$script:MLConfigFile = Join-Path $PSScriptRoot "dns-ml-config.json"

# ML Scoring Weights (can be tuned over time)
$script:DefaultWeights = @{
    ResponseTime = 0.40
    SuccessRate = 0.30
    Jitter = 0.15
    HistoricalTrend = 0.10
    AdvancedFeatures = 0.05
}

# Predefined weight profiles. Pick one with Set-MLProfile.
#   Default   - balanced general-purpose web browsing
#   Gaming    - jitter dominant; latency next; features mostly ignored
#   Streaming - jitter + reliability dominant
#   Browsing  - latency + reliability dominant; jitter tolerated
#   Privacy   - heavy DNSSEC/filtering bonus; latency tolerance higher
$script:WeightProfiles = @{
    Default   = @{ ResponseTime = 0.40; SuccessRate = 0.30; Jitter = 0.15; HistoricalTrend = 0.10; AdvancedFeatures = 0.05 }
    Gaming    = @{ ResponseTime = 0.30; SuccessRate = 0.20; Jitter = 0.40; HistoricalTrend = 0.05; AdvancedFeatures = 0.05 }
    Streaming = @{ ResponseTime = 0.25; SuccessRate = 0.35; Jitter = 0.30; HistoricalTrend = 0.05; AdvancedFeatures = 0.05 }
    Browsing  = @{ ResponseTime = 0.45; SuccessRate = 0.35; Jitter = 0.10; HistoricalTrend = 0.05; AdvancedFeatures = 0.05 }
    Privacy   = @{ ResponseTime = 0.20; SuccessRate = 0.25; Jitter = 0.10; HistoricalTrend = 0.05; AdvancedFeatures = 0.40 }
}

# Tuning constants. Documented here so future contributors don't have to grep.
$script:ScoringConstants = @{
    # Bayesian shrinkage: a brand-new server is regressed toward the population
    # mean until it has accumulated this many tests.
    ShrinkagePriorTests = 5

    # Half-life (days) for stale-data decay. Each metric's contribution is
    # multiplied by 0.5^(daysSinceLastSeen / HalfLifeDays).
    HalfLifeDays = 30.0

    # Minimum samples before percentile normalization kicks in. Below this,
    # we fall back to legacy fixed-basis normalization (200ms RT / 50ms jitter)
    # to avoid degenerate single-point bases.
    MinSamplesForBasis = 3

    # Per-feature bonus on a 0-100 scale. Applied additively to the ranking
    # score (higher = better) BEFORE clamping to [0,100].
    FeatureBonus = @{
        IPv6   = 5
        DNSSEC = 8
        EDNS0  = 3
        TCP    = 3
        Filter = 5    # awarded if any filtering category is blocked
    }

    # Pair diversity bonus on a 0-100 scale.
    DiversityBonus = @{
        DifferentProvider = 6   # different provider name root
        DifferentSubnet24 = 4   # different /24 (correlated-failure resistance)
    }

    # EWMA smoothing factor for trend (0 < a <= 1). Larger = more reactive.
    EWMAAlpha = 0.3
}

#region Helper Functions (Phase 2 scoring infrastructure)

function Get-MLWeights {
    <#
    .SYNOPSIS
    Returns the active scoring weights from the supplied MLData (or the defaults).
    #>
    param([hashtable]$MLData)
    if ($MLData -and $MLData.Weights) { return $MLData.Weights }
    return $script:DefaultWeights
}

function Set-MLWeights {
    <#
    .SYNOPSIS
    Overwrites the active scoring weights on the supplied MLData. The five keys
    (ResponseTime, SuccessRate, Jitter, HistoricalTrend, AdvancedFeatures) are
    each clamped to [0,1] and then renormalized to sum to 1.0.
    #>
    param(
        [Parameter(Mandatory=$true)][hashtable]$MLData,
        [Parameter(Mandatory=$true)][hashtable]$Weights
    )
    $required = @('ResponseTime','SuccessRate','Jitter','HistoricalTrend','AdvancedFeatures')
    $clean = @{}
    foreach ($k in $required) {
        $v = if ($Weights.ContainsKey($k)) { [double]$Weights[$k] } else { [double]$script:DefaultWeights[$k] }
        if ($v -lt 0) { $v = 0 }
        $clean[$k] = $v
    }
    $sum = ($clean.Values | Measure-Object -Sum).Sum
    if ($sum -le 0) { $clean = $script:DefaultWeights.Clone(); $sum = 1.0 }
    foreach ($k in $required) { $clean[$k] = $clean[$k] / $sum }
    $MLData.Weights = $clean
}

function Get-MLProfileNames {
    <# .SYNOPSIS Lists the available weight profile names. #>
    return @($script:WeightProfiles.Keys)
}

function Set-MLProfile {
    <#
    .SYNOPSIS
    Switches the active scoring weights to a named profile.
    #>
    param(
        [Parameter(Mandatory=$true)][hashtable]$MLData,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Default','Gaming','Streaming','Browsing','Privacy')]
        [string]$ProfileName
    )
    Set-MLWeights -MLData $MLData -Weights $script:WeightProfiles[$ProfileName]
    $MLData.ActiveProfile = $ProfileName
}

function Get-MLRankingBasis {
    <#
    .SYNOPSIS
    Computes a per-call normalization basis from the population of currently
    tracked servers. Replaces the legacy hardcoded "200ms = 100 points" /
    "50ms jitter = 100 points" caps with population-relative percentiles, so
    rankings stay fair regardless of the absolute network speed.

    Returns a hashtable with RT and Jitter "saturation" values: a metric at
    or above the saturation value normalizes to 100 (worst), and a metric at
    or below 0 normalizes to 0 (best).
    #>
    param([hashtable]$MLData)

    $defaults = @{ RTBasis = 200.0; JitterBasis = 50.0 }
    if (-not $MLData -or -not $MLData.Servers) { return $defaults }

    $rts = @()
    $jts = @()
    foreach ($s in $MLData.Servers.Values) {
        if ($s.TestCount -gt 0) {
            $rts += ($s.TotalResponseTime / $s.TestCount)
            $jts += ($s.TotalJitter      / $s.TestCount)
        }
    }
    if ($rts.Count -lt $script:ScoringConstants.MinSamplesForBasis) { return $defaults }

    function Get-PercentileLocal {
        param([double[]]$Values, [double]$P)
        $sorted = $Values | Sort-Object
        $rank = ($P / 100.0) * ($sorted.Count - 1)
        $lo = [Math]::Floor($rank); $hi = [Math]::Ceiling($rank)
        if ($lo -eq $hi) { return [double]$sorted[$lo] }
        $w = $rank - $lo
        return ([double]$sorted[$lo] * (1 - $w)) + ([double]$sorted[$hi] * $w)
    }

    # Use the 90th percentile as "worst-acceptable" so a couple of awful outliers
    # don't make every other server look great.
    return @{
        RTBasis     = [Math]::Max(50.0,  (Get-PercentileLocal -Values ([double[]]$rts) -P 90))
        JitterBasis = [Math]::Max(10.0,  (Get-PercentileLocal -Values ([double[]]$jts) -P 90))
    }
}

function Get-StaleDecayWeight {
    <#
    .SYNOPSIS
    Returns a multiplier in (0, 1] that decays exponentially with how long
    ago LastSeen was. Half-life is HalfLifeDays. Recent data => 1.0, old
    data => smaller weight, but never quite zero.
    #>
    param([datetime]$LastSeen, [datetime]$Now = (Get-Date))
    if (-not $LastSeen) { return 1.0 }
    $days = ($Now - $LastSeen).TotalDays
    if ($days -le 0) { return 1.0 }
    $hl = $script:ScoringConstants.HalfLifeDays
    return [Math]::Pow(0.5, $days / $hl)
}

function Get-EWMATrend {
    <#
    .SYNOPSIS
    EWMA-based trend on a score history. Returns positive => improving
    (more recent scores are lower than older scores), negative => degrading.
    Cheaper and smoother than the previous OLS-of-last-10 implementation.
    #>
    param([double[]]$ScoreHistory, [double]$Alpha = 0)
    if (-not $ScoreHistory -or $ScoreHistory.Count -lt 3) { return 0.0 }
    if ($Alpha -le 0) { $Alpha = $script:ScoringConstants.EWMAAlpha }

    # Long-term EMA (alpha/2 = slow), short-term EMA (alpha = fast).
    $slowA = $Alpha / 2.0
    $fastA = $Alpha
    $slow = [double]$ScoreHistory[0]
    $fast = [double]$ScoreHistory[0]
    for ($i = 1; $i -lt $ScoreHistory.Count; $i++) {
        $slow = ($slowA * $ScoreHistory[$i]) + ((1 - $slowA) * $slow)
        $fast = ($fastA * $ScoreHistory[$i]) + ((1 - $fastA) * $fast)
    }
    # Score is "lower=better"; if fast EMA dropped below slow EMA, performance
    # is improving => return positive.
    return ($slow - $fast)
}

function Get-FeatureBonus {
    <#
    .SYNOPSIS
    Returns the additive feature bonus on a 0-100 scale for a server entry.
    #>
    param([hashtable]$ServerData)
    $b = $script:ScoringConstants.FeatureBonus
    $bonus = 0.0
    if ($ServerData.IPv6Capable)   { $bonus += $b.IPv6 }
    if ($ServerData.DNSSECCapable) { $bonus += $b.DNSSEC }
    if ($ServerData.EDNS0Capable)  { $bonus += $b.EDNS0 }
    if ($ServerData.TCPCapable)    { $bonus += $b.TCP }
    if ($ServerData.FilteringCapable) { $bonus += $b.Filter }
    return $bonus
}

function Get-PairDiversityBonus {
    <#
    .SYNOPSIS
    Bonus for primary/secondary pairs that span different providers and
    different /24 subnets (lower correlated-failure risk).
    #>
    param(
        [string]$PrimaryIP, [string]$SecondaryIP,
        [string]$PrimaryProvider, [string]$SecondaryProvider
    )
    $d = $script:ScoringConstants.DiversityBonus
    $bonus = 0.0

    # Different provider name root (strip trailing "Secondary"/"DNS" tokens)
    $rootP = ($PrimaryProvider   -replace '\s+(Secondary|Primary|DNS).*$','').Trim()
    $rootS = ($SecondaryProvider -replace '\s+(Secondary|Primary|DNS).*$','').Trim()
    if ($rootP -and $rootS -and $rootP -ne $rootS) { $bonus += $d.DifferentProvider }

    # Different /24
    if ($PrimaryIP -and $SecondaryIP) {
        $p24 = ($PrimaryIP   -split '\.')[0..2] -join '.'
        $s24 = ($SecondaryIP -split '\.')[0..2] -join '.'
        if ($p24 -ne $s24) { $bonus += $d.DifferentSubnet24 }
    }
    return $bonus
}

#endregion

#region Data Structure Functions

function Initialize-MLData {
    <#
    .SYNOPSIS
    Initialize or load ML training data.
    .PARAMETER DataFile
    Optional override for the on-disk JSON file path. Used by tests to
    isolate from the real persisted data.
    #>
    [CmdletBinding()]
    param(
        [string]$DataFile = $script:MLDataFile
    )

    if (Test-Path $DataFile) {
        try {
            $json = Get-Content $DataFile -Raw | ConvertFrom-Json
            
            return @{
                Servers = ConvertFrom-JsonObject $json.Servers
                Pairs = ConvertFrom-JsonObject $json.Pairs
                LastUpdate = [DateTime]$json.LastUpdate
                TotalRuns = $json.TotalRuns
                Weights = if ($json.Weights) { 
                    ConvertFrom-JsonObject $json.Weights 
                } else { 
                    $script:DefaultWeights 
                }
            }
        } catch {
            $backupPath = "$($DataFile).corrupt-$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
            Write-Warning "Failed to load ML data ($_)."
            try {
                Copy-Item -Path $DataFile -Destination $backupPath -Force -ErrorAction Stop
                Write-Warning "Corrupt ML data file backed up to: $backupPath"
            } catch {
                Write-Warning "Could not back up corrupt ML data file: $_"
            }
            Write-Warning "Starting fresh with empty ML data."
            return Initialize-EmptyMLData
        }
    }
    
    return Initialize-EmptyMLData
}

function Initialize-EmptyMLData {
    return @{
        Servers = @{}
        Pairs = @{}
        LastUpdate = Get-Date
        TotalRuns = 0
        Weights = $script:DefaultWeights
    }
}

function ConvertFrom-JsonObject {
    param($JsonObject)
    
    if ($null -eq $JsonObject) {
        return @{}
    }
    
    $hashtable = @{}
    foreach ($property in $JsonObject.PSObject.Properties) {
        $value = $property.Value
        
        # Recursively convert nested objects
        if ($value -is [PSCustomObject]) {
            $hashtable[$property.Name] = ConvertFrom-JsonObject $value
        } else {
            $hashtable[$property.Name] = $value
        }
    }
    
    return $hashtable
}

function Save-MLData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Data,

        [string]$DataFile = $script:MLDataFile
    )
    
    try {
        $Data.LastUpdate = Get-Date
        $json = $Data | ConvertTo-Json -Depth 20
        $json | Set-Content $DataFile -Force
        return $true
    } catch {
        Write-Warning "Failed to save ML data: $_"
        return $false
    }
}

#endregion

#region Server Tracking Functions

function Update-ServerMLData {
    <#
    .SYNOPSIS
    Updates ML data for a single DNS server based on test results
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$MLData,
        
        [Parameter(Mandatory=$true)]
        [string]$IP,
        
        [Parameter(Mandatory=$true)]
        [string]$Provider,
        
        [Parameter(Mandatory=$true)]
        [double]$ResponseTime,
        
        [Parameter(Mandatory=$true)]
        [double]$SuccessRate,
        
        [Parameter(Mandatory=$true)]
        [double]$Jitter,
        
        [string]$Category = "Unknown",
        [bool]$IPv6Support = $false,
        [bool]$DNSSECSupport = $false,
        [bool]$QualityCheck = $false,
        [bool]$EDNS0Support = $false,
        [bool]$TCPSupport = $false,
        [bool]$FilteringSupport = $false
    )
    
    # Sanitize / clamp inputs so a caller passing the wrong unit (e.g. 0-1 vs 0-100)
    # or a negative value can't permanently poison the running averages.
    if ($ResponseTime -lt 0) { $ResponseTime = 0 }
    if ($Jitter -lt 0)       { $Jitter = 0 }
    
    # Auto-detect 0-1 success rate and convert to 0-100 percentage.
    if ($SuccessRate -gt 0 -and $SuccessRate -le 1.0) {
        $SuccessRate = $SuccessRate * 100.0
    }
    if ($SuccessRate -lt 0)   { $SuccessRate = 0 }
    if ($SuccessRate -gt 100) { $SuccessRate = 100 }
    
    $key = "$IP|$Provider"
    
    if (-not $MLData.Servers.ContainsKey($key)) {
        $MLData.Servers[$key] = @{
            IP = $IP
            Provider = $Provider
            Category = $Category
            TestCount = 0
            TotalResponseTime = 0.0
            TotalSuccessRate = 0.0
            TotalJitter = 0.0
            BestResponseTime = [double]::MaxValue
            WorstResponseTime = 0.0
            LastSeen = Get-Date
            FirstSeen = Get-Date
            IPv6Capable = $false
            DNSSECCapable = $false
            EDNS0Capable = $false
            TCPCapable = $false
            FilteringCapable = $false
            QualityScore = 0.0
            ConsecutiveSuccesses = 0
            ConsecutiveFailures = 0
            ScoreHistory = @()
            PerformanceTrend = 0.0  # Positive = improving, Negative = degrading
        }
    }
    
    $server = $MLData.Servers[$key]
    $server.TestCount++
    $server.TotalResponseTime += $ResponseTime
    $server.TotalSuccessRate += $SuccessRate
    $server.TotalJitter += $Jitter
    $server.LastSeen = Get-Date
    
    # Track best/worst
    if ($ResponseTime -lt $server.BestResponseTime) {
        $server.BestResponseTime = $ResponseTime
    }
    if ($ResponseTime -gt $server.WorstResponseTime) {
        $server.WorstResponseTime = $ResponseTime
    }
    
    # Update advanced features
    if ($IPv6Support)      { $server.IPv6Capable = $true }
    if ($DNSSECSupport)    { $server.DNSSECCapable = $true }
    if ($EDNS0Support)     { $server.EDNS0Capable = $true }
    if ($TCPSupport)       { $server.TCPCapable = $true }
    if ($FilteringSupport) { $server.FilteringCapable = $true }
    
    # Track consecutive performance
    if ($SuccessRate -ge 80) {
        $server.ConsecutiveSuccesses++
        $server.ConsecutiveFailures = 0
    } else {
        $server.ConsecutiveFailures++
        $server.ConsecutiveSuccesses = 0
    }
    
    # Calculate current score using the population-relative basis so trend
    # samples stay comparable across runs.
    $basis = Get-MLRankingBasis -MLData $MLData
    $currentScore = Calculate-ServerScore -ServerData $server -Weights $MLData.Weights -Basis $basis
    
    # Track score history (keep last 50 scores)
    $server.ScoreHistory += $currentScore
    if ($server.ScoreHistory.Count -gt 50) {
        $server.ScoreHistory = $server.ScoreHistory[-50..-1]
    }
    
    # Calculate performance trend (regression analysis on recent scores)
    if ($server.ScoreHistory.Count -ge 5) {
        $server.PerformanceTrend = Calculate-PerformanceTrend -ScoreHistory $server.ScoreHistory
    }
}

function Calculate-ServerScore {
    <#
    .SYNOPSIS
    Calculates a composite ML score for a DNS server.
    Lower scores are better (kept this way for backward compat with existing
    on-disk pair scores). For ranking / display, use Get-RankingScore which
    inverts to a 0-100 "higher = better" view.

    Phase 2 changes:
      - RT and Jitter normalization use a population-derived basis instead of
        the legacy fixed 200ms / 50ms caps. Pass an explicit -Basis hashtable
        to override; omit it for the legacy fallback.
      - Bayesian shrinkage: brand-new servers (TestCount < ShrinkagePriorTests)
        are pulled toward a neutral 50/50/50 score until enough data accrues.
      - Stale-data decay: contributions are scaled down for servers that
        haven't been seen in a while.
      - Feature bonus is applied on a 0-100 scale via Get-FeatureBonus and
        subtracted from the raw score (lower=better).
    #>
    param(
        [Parameter(Mandatory=$true)] [hashtable]$ServerData,
        [Parameter(Mandatory=$true)] [hashtable]$Weights,
        [hashtable]$Basis = $null,
        [datetime]$Now   = (Get-Date)
    )

    if ($ServerData.TestCount -eq 0) { return [double]::MaxValue }

    if (-not $Basis) { $Basis = @{ RTBasis = 200.0; JitterBasis = 50.0 } }

    # Averages
    $avgRT      = $ServerData.TotalResponseTime / $ServerData.TestCount
    $avgSuccess = $ServerData.TotalSuccessRate / $ServerData.TestCount
    $avgJitter  = $ServerData.TotalJitter      / $ServerData.TestCount

    # Normalize to 0-100, lower=better.
    $normRT      = [Math]::Min([Math]::Max($avgRT     / [double]$Basis.RTBasis     * 100, 0), 100)
    $normSuccess = [Math]::Min([Math]::Max((100.0 - $avgSuccess), 0), 100)
    $normJitter  = [Math]::Min([Math]::Max($avgJitter / [double]$Basis.JitterBasis * 100, 0), 100)

    # Bayesian shrinkage toward a neutral 50 until enough samples accrue.
    $prior = $script:ScoringConstants.ShrinkagePriorTests
    if ($prior -gt 0 -and $ServerData.TestCount -lt $prior) {
        $w = $ServerData.TestCount / [double]$prior   # weight of observed data
        $normRT      = ($w * $normRT)      + ((1 - $w) * 50)
        $normSuccess = ($w * $normSuccess) + ((1 - $w) * 50)
        $normJitter  = ($w * $normJitter)  + ((1 - $w) * 50)
    }

    # Trend penalty: PerformanceTrend > 0 = improving (good). We only penalize
    # degradation (negative trend). Convert to 0-100ish penalty via clipping.
    $trendPenalty = 0.0
    if ($ServerData.PerformanceTrend -lt 0) {
        $trendPenalty = [Math]::Min([Math]::Abs($ServerData.PerformanceTrend) * 5, 100)
    }

    # Feature bonus on 0-100 scale (subtracted because lower=better).
    $featureBonus = Get-FeatureBonus -ServerData $ServerData

    # Composite (raw)
    $score = ($normRT      * $Weights.ResponseTime)     +
             ($normSuccess * $Weights.SuccessRate)      +
             ($normJitter  * $Weights.Jitter)           +
             ($trendPenalty * $Weights.HistoricalTrend) -
             ($featureBonus * $Weights.AdvancedFeatures)

    # Reliability multipliers (kept from legacy scorer; bounded so a long
    # streak can't NaN-out the score).
    if ($ServerData.ConsecutiveFailures -gt 0) {
        $mult = 1 + [Math]::Min($ServerData.ConsecutiveFailures * 0.2, 2.0)
        $score *= $mult
    }
    if ($ServerData.ConsecutiveSuccesses -ge 5) {
        $score *= 0.9
    }

    # Stale-data decay: nudge the score back toward the neutral midpoint for
    # very old observations so a server that hasn't been re-tested in months
    # doesn't permanently dominate the leaderboard.
    if ($ServerData.LastSeen) {
        $decay = Get-StaleDecayWeight -LastSeen $ServerData.LastSeen -Now $Now
        $score = ($decay * $score) + ((1 - $decay) * 50.0)
    }

    return [Math]::Max($score, 0)
}

function Get-RankingScore {
    <#
    .SYNOPSIS
    Returns a 0-100 "higher=better" view of a server's composite score.
    Use this for sorting, recommendations, and display.
    #>
    param(
        [Parameter(Mandatory=$true)] [hashtable]$ServerData,
        [Parameter(Mandatory=$true)] [hashtable]$Weights,
        [hashtable]$Basis = $null,
        [datetime]$Now   = (Get-Date)
    )
    $raw = Calculate-ServerScore -ServerData $ServerData -Weights $Weights -Basis $Basis -Now $Now
    if ($raw -ge [double]::MaxValue) { return 0.0 }
    return [Math]::Max(0, [Math]::Min(100, 100.0 - $raw))
}

function Calculate-PerformanceTrend {
    <#
    .SYNOPSIS
    Calculates the performance trend of a server's recent score history.
    Positive => improving (recent scores are lower than older scores).
    Negative => degrading.

    Phase 2: replaced "OLS slope on last 10" with EWMA-based trend, which is
    smoother, cheaper, and self-bounding. The full ScoreHistory is used so
    long-term degradation past the previous 10-sample window is still visible.
    #>
    param([array]$ScoreHistory)
    if (-not $ScoreHistory -or $ScoreHistory.Count -lt 2) { return 0.0 }
    return Get-EWMATrend -ScoreHistory ([double[]]$ScoreHistory)
}

#endregion

#region Pair Tracking Functions

function Update-PairMLData {
    <#
    .SYNOPSIS
    Updates ML data for a DNS pair configuration
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$MLData,
        
        [Parameter(Mandatory=$true)]
        [string]$PrimaryIP,
        
        [Parameter(Mandatory=$true)]
        [string]$SecondaryIP,
        
        [Parameter(Mandatory=$true)]
        [string]$PrimaryProvider,
        
        [Parameter(Mandatory=$true)]
        [string]$SecondaryProvider,
        
        [Parameter(Mandatory=$true)]
        [double]$CombinedScore,
        
        [string]$ConfigType = "Unknown"  # e.g., "Best Overall", "Same Provider", "Mixed"
    )
    
    $key = "$PrimaryIP|$SecondaryIP"
    
    # Apply pair-diversity bonus by *reducing* the combined score (lower=better)
    # so diverse pairs are preferred for ties. Bonus is on a 0-100 scale.
    $diversityBonus = Get-PairDiversityBonus `
        -PrimaryIP $PrimaryIP -SecondaryIP $SecondaryIP `
        -PrimaryProvider $PrimaryProvider -SecondaryProvider $SecondaryProvider
    $adjustedScore = [Math]::Max(0, $CombinedScore - $diversityBonus)
    
    if (-not $MLData.Pairs.ContainsKey($key)) {
        $MLData.Pairs[$key] = @{
            PrimaryIP = $PrimaryIP
            SecondaryIP = $SecondaryIP
            PrimaryProvider = $PrimaryProvider
            SecondaryProvider = $SecondaryProvider
            ConfigType = $ConfigType
            TestCount = 0
            TotalScore = 0.0
            BestScore = [double]::MaxValue
            DiversityBonus = $diversityBonus
            LastSeen = Get-Date
            FirstSeen = Get-Date
            TimesRecommended = 0
            SuccessfulConfigurations = 0
        }
    }
    
    $pair = $MLData.Pairs[$key]
    $pair.TestCount++
    $pair.TotalScore += $adjustedScore
    $pair.LastSeen = Get-Date
    $pair.DiversityBonus = $diversityBonus
    
    if ($adjustedScore -lt $pair.BestScore) {
        $pair.BestScore = $adjustedScore
    }
}

function Get-TopMLPairs {
    <#
    .SYNOPSIS
    Gets the top-ranked DNS pairs based on ML scoring
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$MLData,
        
        [int]$TopN = 10,
        
        [string]$ConfigType = $null  # Filter by config type
    )
    
    $pairs = $MLData.Pairs.Values | ForEach-Object {
        [PSCustomObject]@{
            PrimaryIP = $_.PrimaryIP
            SecondaryIP = $_.SecondaryIP
            PrimaryProvider = $_.PrimaryProvider
            SecondaryProvider = $_.SecondaryProvider
            ConfigType = $_.ConfigType
            TestCount = $_.TestCount
            AverageScore = if ($_.TestCount -gt 0) { $_.TotalScore / $_.TestCount } else { [double]::MaxValue }
            BestScore = $_.BestScore
            LastSeen = $_.LastSeen
            TimesRecommended = $_.TimesRecommended
        }
    }
    
    if ($ConfigType) {
        $pairs = $pairs | Where-Object { $_.ConfigType -eq $ConfigType }
    }
    
    # Filter: must have at least 2 test runs to be considered
    $pairs = $pairs | Where-Object { $_.TestCount -ge 2 }
    
    return $pairs | Sort-Object AverageScore | Select-Object -First $TopN
}

#endregion

#region Server Prioritization Functions

function Get-PrioritizedServers {
    <#
    .SYNOPSIS
    Returns a prioritized list of DNS servers to test, with ML-learned best performers first
    #>
    param(
        [Parameter(Mandatory=$true)]
        [array]$AllServers,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$MLData
    )
    
    $prioritized = @()
    $unprioritized = @()
    
    # Compute the per-call normalization basis once so all server scores are
    # comparable on the same scale.
    $basis = Get-MLRankingBasis -MLData $MLData
    $now   = Get-Date

    foreach ($server in $AllServers) {
        $key = "$($server.IP)|$($server.Name)"
        
        if ($MLData.Servers.ContainsKey($key)) {
            $mlServer = $MLData.Servers[$key]
            $score = Calculate-ServerScore -ServerData $mlServer -Weights $MLData.Weights -Basis $basis -Now $now
            
            # Add to prioritized list with score
            $prioritized += [PSCustomObject]@{
                Server = $server
                MLScore = $score
                TestCount = $mlServer.TestCount
                ConsecutiveSuccesses = $mlServer.ConsecutiveSuccesses
            }
        } else {
            # Unknown server - add to unprioritized
            $unprioritized += [PSCustomObject]@{
                Server = $server
                MLScore = [double]::MaxValue
                TestCount = 0
                ConsecutiveSuccesses = 0
            }
        }
    }
    
    # Sort prioritized by ML score (lower is better)
    $sortedPrioritized = $prioritized | Sort-Object MLScore
    
    # Combine: best ML-learned servers first, then unknowns (for exploration)
    $finalList = @()
    $finalList += $sortedPrioritized | ForEach-Object { $_.Server }
    $finalList += $unprioritized | ForEach-Object { $_.Server }
    
    return $finalList
}

function Get-MLRecommendedPair {
    <#
    .SYNOPSIS
    Gets the ML-recommended DNS pair based on historical learning
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$MLData,
        
        [string]$PreferredType = "Best Overall"  # or "Same Provider", "Mixed", etc.
    )
    
    $topPairs = Get-TopMLPairs -MLData $MLData -TopN 5 -ConfigType $PreferredType
    
    if ($topPairs.Count -eq 0) {
        # No historical data, return null
        return $null
    }
    
    # Return the best pair
    $bestPair = $topPairs[0]
    
    # Increment recommendation counter
    $key = "$($bestPair.PrimaryIP)|$($bestPair.SecondaryIP)"
    if ($MLData.Pairs.ContainsKey($key)) {
        $MLData.Pairs[$key].TimesRecommended++
    }
    
    return $bestPair
}

#endregion

#region Integration Functions

function Export-MLRecommendations {
    <#
    .SYNOPSIS
    Exports ML recommendations to a human-readable report
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$MLData,
        
        [string]$OutputPath = "dns-ml-recommendations.txt"
    )
    
    $report = @"
========================================
DNS Machine Learning Recommendations
========================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Total Training Runs: $($MLData.TotalRuns)
Last Update: $($MLData.LastUpdate)

========================================
TOP 10 INDIVIDUAL DNS SERVERS
========================================

"@
    
    # Get top 10 servers
    $topServers = $MLData.Servers.Values | ForEach-Object {
        [PSCustomObject]@{
            Provider = $_.Provider
            IP = $_.IP
            Category = $_.Category
            Score = Calculate-ServerScore -ServerData $_ -Weights $MLData.Weights
            TestCount = $_.TestCount
            AvgResponseTime = if ($_.TestCount -gt 0) { [Math]::Round($_.TotalResponseTime / $_.TestCount, 2) } else { 0 }
            AvgSuccessRate = if ($_.TestCount -gt 0) { [Math]::Round($_.TotalSuccessRate / $_.TestCount, 1) } else { 0 }
            Trend = if ($_.PerformanceTrend -gt 0) { "↑ Improving" } elseif ($_.PerformanceTrend -lt -0.1) { "↓ Degrading" } else { "→ Stable" }
        }
    } | Where-Object { $_.TestCount -ge 2 } | Sort-Object Score | Select-Object -First 10
    
    foreach ($server in $topServers) {
        $report += @"
$($server.Provider) ($($server.IP))
  Category: $($server.Category)
  ML Score: $([Math]::Round($server.Score, 2)) (lower is better)
  Avg Response: $($server.AvgResponseTime) ms
  Avg Success Rate: $($server.AvgSuccessRate)%
  Tests: $($server.TestCount)
  Trend: $($server.Trend)

"@
    }
    
    $report += @"

========================================
TOP 5 DNS PAIR CONFIGURATIONS
========================================

"@
    
    $topPairs = Get-TopMLPairs -MLData $MLData -TopN 5
    
    foreach ($pair in $topPairs) {
        $report += @"
Primary: $($pair.PrimaryProvider) ($($pair.PrimaryIP))
Secondary: $($pair.SecondaryProvider) ($($pair.SecondaryIP))
  Type: $($pair.ConfigType)
  ML Score: $([Math]::Round($pair.AverageScore, 2))
  Tests: $($pair.TestCount)
  Best Score: $([Math]::Round($pair.BestScore, 2))
  Times Recommended: $($pair.TimesRecommended)
  Last Seen: $($pair.LastSeen)

"@
    }
    
    $report | Out-File $OutputPath -Encoding UTF8
    Write-Host "ML recommendations exported to: $OutputPath" -ForegroundColor Green
}

#endregion

# Export public functions
Export-ModuleMember -Function @(
    'Initialize-MLData',
    'Save-MLData',
    'Update-ServerMLData',
    'Update-PairMLData',
    'Get-PrioritizedServers',
    'Get-TopMLPairs',
    'Get-MLRecommendedPair',
    'Export-MLRecommendations',
    'Get-MLWeights',
    'Set-MLWeights',
    'Set-MLProfile',
    'Get-MLProfileNames',
    'Get-MLRankingBasis',
    'Get-RankingScore',
    'Get-PairDiversityBonus',
    'Calculate-ServerScore'
)
