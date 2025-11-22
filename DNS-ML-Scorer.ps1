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

#region Data Structure Functions

function Initialize-MLData {
    <#
    .SYNOPSIS
    Initialize or load ML training data
    #>
    
    if (Test-Path $script:MLDataFile) {
        try {
            $json = Get-Content $script:MLDataFile -Raw | ConvertFrom-Json
            
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
            Write-Warning "Failed to load ML data, starting fresh: $_"
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
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Data
    )
    
    try {
        $Data.LastUpdate = Get-Date
        $json = $Data | ConvertTo-Json -Depth 20
        $json | Set-Content $script:MLDataFile -Force
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
        [bool]$QualityCheck = $false
    )
    
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
    if ($IPv6Support) { $server.IPv6Capable = $true }
    if ($DNSSECSupport) { $server.DNSSECCapable = $true }
    
    # Track consecutive performance
    if ($SuccessRate -ge 80) {
        $server.ConsecutiveSuccesses++
        $server.ConsecutiveFailures = 0
    } else {
        $server.ConsecutiveFailures++
        $server.ConsecutiveSuccesses = 0
    }
    
    # Calculate current score
    $currentScore = Calculate-ServerScore -ServerData $server -Weights $MLData.Weights
    
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
    Calculates a composite ML score for a DNS server
    Lower scores are better (optimized for speed and reliability)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$ServerData,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Weights
    )
    
    if ($ServerData.TestCount -eq 0) {
        return [double]::MaxValue
    }
    
    # Calculate averages
    $avgResponseTime = $ServerData.TotalResponseTime / $ServerData.TestCount
    $avgSuccessRate = $ServerData.TotalSuccessRate / $ServerData.TestCount
    $avgJitter = $ServerData.TotalJitter / $ServerData.TestCount
    
    # Normalize metrics (0-100 scale)
    $normalizedRT = [Math]::Min($avgResponseTime / 200.0 * 100, 100)  # 200ms = 100 points
    $normalizedSuccess = (100 - $avgSuccessRate)  # Invert so lower is better
    $normalizedJitter = [Math]::Min($avgJitter / 50.0 * 100, 100)  # 50ms jitter = 100 points
    
    # Historical trend component (negative trend = degrading = higher score)
    $trendPenalty = if ($ServerData.PerformanceTrend -lt 0) { 
        [Math]::Abs($ServerData.PerformanceTrend) * 10 
    } else { 
        0 
    }
    
    # Advanced features bonus (reduces score if supported)
    $featureBonus = 0
    if ($ServerData.IPv6Capable) { $featureBonus += 2 }
    if ($ServerData.DNSSECCapable) { $featureBonus += 3 }
    
    # Composite score
    $score = ($normalizedRT * $Weights.ResponseTime) + 
             ($normalizedSuccess * $Weights.SuccessRate) + 
             ($normalizedJitter * $Weights.Jitter) + 
             ($trendPenalty * $Weights.HistoricalTrend) - 
             ($featureBonus * $Weights.AdvancedFeatures)
    
    # Apply reliability multiplier (consecutive failures increase score)
    if ($ServerData.ConsecutiveFailures -gt 0) {
        $score *= (1 + ($ServerData.ConsecutiveFailures * 0.2))
    }
    
    # Apply consistency bonus (consecutive successes decrease score)
    if ($ServerData.ConsecutiveSuccesses -ge 5) {
        $score *= 0.9
    }
    
    return [Math]::Max($score, 0)
}

function Calculate-PerformanceTrend {
    <#
    .SYNOPSIS
    Calculates performance trend using simple linear regression
    Positive = improving, Negative = degrading
    #>
    param(
        [array]$ScoreHistory
    )
    
    if ($ScoreHistory.Count -lt 2) {
        return 0.0
    }
    
    $n = $ScoreHistory.Count
    $recentScores = $ScoreHistory[-10..-1]  # Last 10 scores
    $n = $recentScores.Count
    
    $sumX = 0
    $sumY = 0
    $sumXY = 0
    $sumX2 = 0
    
    for ($i = 0; $i -lt $n; $i++) {
        $x = $i
        $y = $recentScores[$i]
        $sumX += $x
        $sumY += $y
        $sumXY += ($x * $y)
        $sumX2 += ($x * $x)
    }
    
    # Calculate slope (trend)
    $denominator = ($n * $sumX2) - ($sumX * $sumX)
    if ($denominator -eq 0) {
        return 0.0
    }
    
    $slope = (($n * $sumXY) - ($sumX * $sumY)) / $denominator
    
    # Invert slope (decreasing score = improving performance = positive trend)
    return -$slope
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
            LastSeen = Get-Date
            FirstSeen = Get-Date
            TimesRecommended = 0
            SuccessfulConfigurations = 0
        }
    }
    
    $pair = $MLData.Pairs[$key]
    $pair.TestCount++
    $pair.TotalScore += $CombinedScore
    $pair.LastSeen = Get-Date
    
    if ($CombinedScore -lt $pair.BestScore) {
        $pair.BestScore = $CombinedScore
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
    
    foreach ($server in $AllServers) {
        $key = "$($server.IP)|$($server.Name)"
        
        if ($MLData.Servers.ContainsKey($key)) {
            $mlServer = $MLData.Servers[$key]
            $score = Calculate-ServerScore -ServerData $mlServer -Weights $MLData.Weights
            
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
    'Export-MLRecommendations'
)
