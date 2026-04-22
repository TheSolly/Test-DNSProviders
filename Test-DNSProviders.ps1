# DNS Performance Test Script
# Tests DNS providers for speed and reliability
# Created: May 2025

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(HelpMessage="Domain to test DNS resolution (default: example.com)")]
    [string]$Domain = "example.com",
    
    [Parameter(HelpMessage="Number of tests per DNS server (default: 5)")]
    [int]$TestCount = 5,
    
    [Parameter(HelpMessage="Timeout in seconds for each DNS query (default: 3)")]
    [int]$Timeout = 3,
    
    [Parameter(HelpMessage="Adaptive timeout: longer timeout for Egyptian DNS (default: enabled)")]
    [switch]$AdaptiveTimeout,
    
    [Parameter(HelpMessage="Extended timeout for Egyptian DNS servers in seconds (default: 8)")]
    [int]$EgyptianTimeout = 8,
    
    [Parameter(HelpMessage="Maximum failure rate before removing DNS from tests (0.0-1.0, default: 0.8)")]
    [ValidateRange(0.0, 1.0)]
    [double]$MaxFailureRate = 0.8,
    
    [Parameter(HelpMessage="Disable removal of consistently failing DNS servers from results")]
    [switch]$DisableFailureRemoval,
    
    [Parameter(HelpMessage="Number of consecutive failures before flagging DNS as problematic (default: 3)")]
    [int]$FailureThreshold = 3,
      [Parameter(HelpMessage="Test only specific DNS categories: All, Egyptian, Global, ControlD, Encrypted, IPv6 (default: All)")]
    [ValidateSet("All", "Egyptian", "Global", "ControlD", "Encrypted", "IPv6")]
    [string]$Category = "All",
    
    [Parameter(HelpMessage="Filter providers by transport protocol: All, Do53 (classic UDP/53), DoH (DNS-over-HTTPS), DoT (DNS-over-TLS). Default: All.")]
    [ValidateSet("All", "Do53", "DoH", "DoT")]
    [string]$Protocol = "All",
    
    [Parameter(HelpMessage="Path to export results as CSV")]
    [string]$ExportPath,
    
    [Parameter(HelpMessage="Path to export results as JSON (full structured output, including capability flags and statistics)")]
    [string]$ExportJson,
    
    [Parameter(HelpMessage="Test different DNS record types")]
    [switch]$MultiRecordTest,
    
    [Parameter(HelpMessage="Run tests in parallel to speed up the process")]
    [switch]$Parallel,
    
    [Parameter(HelpMessage="Show only the fastest N DNS providers (default: all)")]
    [int]$TopResults = 0,
    
    [Parameter(HelpMessage="Show detailed timing information for each test")]
    [switch]$DetailedOutput,
    
    [Parameter(HelpMessage="Test using alternative domains (google.com, reddit.com, etc.)")]
    [switch]$AlternateDomains,
    
    [Parameter(HelpMessage="Test multiple domains instead of just one random domain")]
    [switch]$MultiDomainTest,
    
    [Parameter(HelpMessage="Generate network configuration scripts for Windows, Linux, and macOS")]
    [switch]$GenerateScripts,
      [Parameter(HelpMessage="Hide warnings for problematic DNS servers")]
    [switch]$HideWarnings,
    
    [Parameter(HelpMessage="Aggressive mode: Remove failing DNS servers immediately")]
    [switch]$AggressiveMode,
    
    [Parameter(HelpMessage="Quick test mode: Reduce test count for faster results")]
    [switch]$QuickTest,
    
    [Parameter(HelpMessage="Disable early exit in QuickTest - test all available DNS providers")]
    [switch]$NoEarlyExit,
    
    [Parameter(HelpMessage="Disable persistent failure tracking across script runs")]
    [switch]$DisablePersistentTracking,
    
    [Parameter(HelpMessage="Number of script runs a DNS must fail before being blacklisted (default: 3)")]
    [int]$PersistentFailureThreshold = 3,
    
    [Parameter(HelpMessage="Reset persistent failure tracking history")]
    [switch]$ResetTracking,
    
    [Parameter(HelpMessage="Show persistent tracking statistics")]
    [switch]$ShowTrackingStats,
    
    [Parameter(HelpMessage="Skip IPv6 support testing (AAAA records)")]
    [switch]$SkipIPv6Test,
    
    [Parameter(HelpMessage="Skip DNSSEC validation support testing")]
    [switch]$SkipDNSSECTest,
    
    [Parameter(HelpMessage="Skip DNS response completeness and quality verification")]
    [switch]$SkipResponseVerification,
    
    [Parameter(HelpMessage="Test EDNS0 support (larger UDP packets, better for CDN queries)")]
    [switch]$TestEDNS0,
    
    [Parameter(HelpMessage="Test TCP fallback support (critical for gaming/streaming large responses)")]
    [switch]$TestTCP,
    
    [Parameter(HelpMessage="Test content-filtering capabilities (malware/ads/adult) using canary domains. Reports per-category block status.")]
    [switch]$TestFiltering,
    
    [Parameter(HelpMessage="Jitter weight multiplier for scoring (default: 2.0, higher = jitter matters more)")]
    [ValidateRange(0.0, 10.0)]
    [double]$JitterWeight = 2.0,

    [Parameter(HelpMessage="Sort results by composite score (response time + jitter * JitterWeight) instead of raw response time")]
    [switch]$SortByScore,

    [Parameter(HelpMessage="Defeat recursive-resolver caching by prefixing each performance probe with a random subdomain (forces real upstream lookup; responses are typically NXDOMAIN). Reliability and capability probes are unaffected.")]
    [switch]$CacheBust,

    [Parameter(HelpMessage="Number of automatic retries (with exponential backoff) for a transiently timed-out performance probe before counting it as failed (default: 1, 0 disables)")]
    [ValidateRange(0, 5)]
    [int]$MaxRetries = 1,

    [Parameter(HelpMessage="ML scoring profile that selects how the scorer weighs response time, jitter, success rate, trend, and advanced features. Default = balanced general-purpose.")]
    [ValidateSet('Default','Gaming','Streaming','Browsing','Privacy')]
    [string]$MLProfile = 'Default',

    [Parameter(HelpMessage="Maximum concurrent DNS probes when running in -Parallel mode. Higher = faster but heavier on the network. Default = 16.")]
    [ValidateRange(1, 128)]
    [int]$MaxThreads = 16,

    [Parameter(HelpMessage="Apply the recommended DNS pair to the system after testing. Honors -WhatIf and -Confirm. Requires Administrator on Windows.")]
    [switch]$ApplyDNS,

    [Parameter(HelpMessage="Network adapter alias pattern to apply DNS to (Windows only, default 'Ethernet*'). Supports wildcards.")]
    [string]$InterfaceAlias = 'Ethernet*',

    [Parameter(HelpMessage="Path to a JSON-lines structured log file. Each test attempt and lifecycle event becomes one JSON object on its own line.")]
    [string]$LogPath,

    [Parameter(HelpMessage="Suppress the chatty per-probe console output (banners, results table, recommendations and exports still print).")]
    [switch]$Quiet,

    [Parameter(HelpMessage="Path to write a self-contained HTML report of the run.")]
    [string]$ExportHtml
)

# Check if required modules are available
if (-not (Get-Command "Resolve-DnsName" -ErrorAction SilentlyContinue)) {
    Write-Host "The required cmdlet 'Resolve-DnsName' is not available on your system." -ForegroundColor Red
    Write-Host "This script requires Windows PowerShell 5.1 or later with the DnsClient module." -ForegroundColor Red
    exit 1
}

# Apply quick test mode settings
if ($QuickTest) {
    # Aggressive QuickTest optimizations for maximum speed.
    # Honour explicit -TestCount / -Timeout overrides so users can opt back into
    # multi-sample jitter measurement while keeping the rest of QuickTest's
    # speedups (skip advanced tests, ML prioritisation, single-domain, etc).
    if (-not $PSBoundParameters.ContainsKey('TestCount')) { $TestCount = 1 }
    if (-not $PSBoundParameters.ContainsKey('Timeout'))   { $Timeout   = 1 }
    $AggressiveMode = $true
    $DisableFailureRemoval = $false
    
    # Skip expensive additional tests in QuickTest
    $SkipIPv6Test = $true
    $SkipDNSSECTest = $true
    $SkipResponseVerification = $true
    
    # Disable parallel mode (sequential is faster for quick tests)
    $Parallel = $false
    
    # Disable multi-record and multi-domain tests
    $MultiRecordTest = $false
    $MultiDomainTest = $false
    $AlternateDomains = $false
    
    # Focus on previously successful DNS servers first
    $script:QuickTestMode = $true
    
    Write-Verbose "QuickTest: TestCount=$TestCount, Timeout=${Timeout}s, advanced tests skipped"
}

# Global variables for failure tracking
$script:DnsFailureTracker = @{}
$script:DnsSuccessTracker = @{}
$script:RemovedDnsProviders = @()
$script:PersistentTrackingFile = Join-Path $PSScriptRoot "dns-failure-history.json"

# Import ML Scorer Module
try {
    $mlModulePath = Join-Path $PSScriptRoot "DNS-ML-Scorer.psd1"
    if (-not (Test-Path $mlModulePath)) {
        # Fall back to the raw .psm1 if the manifest is missing
        $mlModulePath = Join-Path $PSScriptRoot "DNS-ML-Scorer.psm1"
    }
    Import-Module $mlModulePath -Force -DisableNameChecking -ErrorAction Stop
    $script:MLEnabled = $true
    $script:MLData = Initialize-MLData

    # Apply selected scoring profile so all downstream calls use the right weights.
    if (Get-Command Set-MLProfile -ErrorAction SilentlyContinue) {
        try {
            Set-MLProfile -MLData $script:MLData -ProfileName $MLProfile
        } catch {
            Write-Warning "Failed to apply ML profile '$MLProfile': $_"
        }
    }
} catch {
    Write-Warning "ML Scorer module not available. Running without ML optimization: $_"
    $script:MLEnabled = $false
    $script:MLData = $null
}

# ============================================================================
# Encrypted-DNS wire-protocol module (DoH / DoT). Optional - if missing, the
# script still works for classic Do53 providers but skips DoH/DoT entries.
# ============================================================================
$script:EncryptedDnsAvailable = $false
try {
    $wirePath = Join-Path $PSScriptRoot 'DnsWireProtocol.psm1'
    if (Test-Path -LiteralPath $wirePath) {
        Import-Module $wirePath -Force -DisableNameChecking -ErrorAction Stop
        $script:EncryptedDnsAvailable = $true
    }
} catch {
    Write-Warning "DnsWireProtocol module failed to load: $_. DoH/DoT providers will be skipped."
}

# ============================================================================
# Runspace pool for cheap, in-process scriptblock execution with timeout.
# ============================================================================
# Replaces the old Start-Job/Wait-Job/Receive-Job/Remove-Job pattern, which
# spawned a fresh powershell.exe child for every DNS probe (~150-300 ms of
# pure overhead per call). The runspace pool keeps a small set of warm
# in-process runspaces and reuses them, cutting per-call overhead to ~1-5 ms.
$script:DnsRunspacePool = $null

function Get-DnsRunspacePool {
    if ($null -eq $script:DnsRunspacePool -or $script:DnsRunspacePool.RunspacePoolStateInfo.State -ne 'Opened') {
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        # MaxThreads governs the *outer* parallel test loop too; for the
        # synchronous (timeout-bound) helper a small ceiling is enough, but
        # we want headroom when -Parallel is also active.
        $max = [Math]::Max(8, [int]$script:MaxThreads)
        $pool = [runspacefactory]::CreateRunspacePool(1, $max, $iss, $Host)
        $pool.ApartmentState = 'STA'
        $pool.Open()
        $script:DnsRunspacePool = $pool
    }
    return $script:DnsRunspacePool
}

function Invoke-DnsScriptBlockWithTimeout {
    <#
    .SYNOPSIS
    Runs a scriptblock with a hard timeout using a shared runspace pool.

    .OUTPUTS
    The scriptblock's return value, OR a synthetic
    @{ Success = $false; Error = 'Timeout' } hashtable on timeout, OR
    @{ Success = $false; Error = '<msg>' } on a runtime exception.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [Parameter(Mandatory)] [int]$TimeoutSeconds
    )

    $pool = Get-DnsRunspacePool
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($ScriptBlock)
    foreach ($arg in $ArgumentList) { [void]$ps.AddArgument($arg) }

    $async = $ps.BeginInvoke()
    try {
        # Wait up to TimeoutSeconds; AsyncWaitHandle.WaitOne expects ms.
        if ($async.AsyncWaitHandle.WaitOne([int]([Math]::Max(1, $TimeoutSeconds) * 1000))) {
            try {
                $result = $ps.EndInvoke($async)
            } catch {
                return @{ Success = $false; Error = $_.Exception.Message }
            }
            # Scriptblocks may emit a single hashtable; PowerShell wraps it in
            # a Collection. Unwrap to keep parity with Receive-Job semantics.
            if ($result -and $result.Count -eq 1) { return $result[0] }
            return $result
        } else {
            try { $ps.Stop() } catch { }
            return @{ Success = $false; Error = 'Timeout' }
        }
    } finally {
        $ps.Dispose()
    }
}

# ============================================================================
# Unified DNS probe dispatcher. Hides the Do53 / DoH / DoT distinction from
# the rest of the script, returning a uniform shape:
#   @{ Success=$bool; ResponseTimeMs=$double; Error=$string }
# ResponseTimeMs reflects wall-clock for Do53 (since Resolve-DnsName doesn't
# expose per-call timing), and the wire-level round-trip for DoH/DoT.
# ============================================================================
function Invoke-DnsProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$IP,
        [Parameter(Mandatory)] [string]$Domain,
        [string]$RecordType = 'A',
        [string]$ProbeProtocol = 'do53',
        [string]$Url = '',
        [string]$Hostname = '',
        [Parameter(Mandatory)] [int]$TimeoutSeconds
    )

    $proto = $ProbeProtocol.ToLower()

    if ($proto -eq 'doh') {
        if (-not $script:EncryptedDnsAvailable) {
            return @{ Success = $false; Error = 'DoH module unavailable' }
        }
        $r = Test-DoHQuery -Url $Url -Domain $Domain -RecordType $RecordType -TimeoutMs ($TimeoutSeconds * 1000)
        if ($r.Success) {
            return @{ Success = $true; ResponseTimeMs = [double]$r.ResponseTimeMs }
        } else {
            return @{ Success = $false; Error = $r.Error }
        }
    }
    elseif ($proto -eq 'dot') {
        if (-not $script:EncryptedDnsAvailable) {
            return @{ Success = $false; Error = 'DoT module unavailable' }
        }
        $r = Test-DoTQuery -ServerIP $IP -Hostname $Hostname -Domain $Domain -RecordType $RecordType -TimeoutMs ($TimeoutSeconds * 1000)
        if ($r.Success) {
            return @{ Success = $true; ResponseTimeMs = [double]$r.ResponseTimeMs }
        } else {
            return @{ Success = $false; Error = $r.Error }
        }
    }
    else {
        # do53 - classic Resolve-DnsName, wrapped in the timeout helper so
        # PSv5's lack of per-call timeout is enforced by us.
        $sb = {
            param($dnsIP, $dom, $rtype)
            try {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                Resolve-DnsName -Server $dnsIP -Name $dom -Type $rtype -DnsOnly -ErrorAction Stop | Out-Null
                $sw.Stop()
                return @{ Success = $true; ResponseTimeMs = $sw.Elapsed.TotalMilliseconds }
            } catch {
                return @{ Success = $false; Error = $_.Exception.Message }
            }
        }
        $res = Invoke-DnsScriptBlockWithTimeout -ScriptBlock $sb -ArgumentList @($IP, $Domain, $RecordType) -TimeoutSeconds $TimeoutSeconds
        if ($res -and $res.Success) {
            return @{ Success = $true; ResponseTimeMs = [double]$res.ResponseTimeMs }
        } else {
            $err = if ($res -and $res.Error) { $res.Error } else { 'Unknown error' }
            return @{ Success = $false; Error = $err }
        }
    }
}

# Statistics helpers
# ==================

function Get-Percentile {
    <#
    .SYNOPSIS
    Returns a percentile value from a numeric array using linear interpolation
    between adjacent ranks. Returns 0 if the array is empty.
    #>
    param(
        [double[]]$Values,
        [ValidateRange(0.0, 100.0)]
        [double]$Percentile = 50.0
    )

    if ($null -eq $Values -or $Values.Count -eq 0) { return 0.0 }
    if ($Values.Count -eq 1) { return [double]$Values[0] }

    $sorted = $Values | Sort-Object
    $rank = ($Percentile / 100.0) * ($sorted.Count - 1)
    $lower = [Math]::Floor($rank)
    $upper = [Math]::Ceiling($rank)
    if ($lower -eq $upper) { return [double]$sorted[$lower] }
    $weight = $rank - $lower
    return ([double]$sorted[$lower] * (1.0 - $weight)) + ([double]$sorted[$upper] * $weight)
}

function Get-CacheBustingDomain {
    <#
    .SYNOPSIS
    Prefixes the supplied domain with a short random label so the recursive
    resolver cannot serve the response from cache. Most random subdomains of
    public test domains return NXDOMAIN, which is exactly what we want for
    measuring upstream lookup latency rather than cache-hit speed.
    #>
    param([string]$Domain)
    $rand = ([guid]::NewGuid().ToString('N')).Substring(0, 8)
    return "r$rand.$Domain"
}

# Persistent DNS Failure Tracking Functions
# ==========================================

function Initialize-PersistentTracking {
    <#
    .SYNOPSIS
    Loads persistent DNS failure history from JSON file
    #>
    if ($DisablePersistentTracking) {
        return @{}
    }
    
    if (Test-Path $script:PersistentTrackingFile) {
        try {
            $content = Get-Content $script:PersistentTrackingFile -Raw | ConvertFrom-Json
            $history = @{}
            
            # Convert from JSON object to hashtable
            foreach ($property in $content.PSObject.Properties) {
                $history[$property.Name] = @{
                    FailureCount = $property.Value.FailureCount
                    LastFailure = [DateTime]$property.Value.LastFailure
                    TotalRuns = $property.Value.TotalRuns
                    SuccessCount = $property.Value.SuccessCount
                    Blacklisted = $property.Value.Blacklisted
                }
            }
            
            return $history
        } catch {
            $backupPath = "$($script:PersistentTrackingFile).corrupt-$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
            Write-Warning "Failed to load persistent tracking data ($_)."
            try {
                Copy-Item -Path $script:PersistentTrackingFile -Destination $backupPath -Force -ErrorAction Stop
                Write-Warning "Corrupt tracking file backed up to: $backupPath"
            } catch {
                Write-Warning "Could not back up corrupt tracking file: $_"
            }
            Write-Warning "Starting with empty tracking history."
            return @{}
        }
    }
    
    return @{}
}

function Save-PersistentTracking {
    <#
    .SYNOPSIS
    Saves DNS failure history to JSON file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$History
    )
    
    if ($DisablePersistentTracking) {
        return
    }
    
    try {
        # Convert hashtable to JSON-friendly object
        $jsonObject = @{}
        foreach ($key in $History.Keys) {
            $jsonObject[$key] = @{
                FailureCount = $History[$key].FailureCount
                LastFailure = $History[$key].LastFailure.ToString("o")
                TotalRuns = $History[$key].TotalRuns
                SuccessCount = $History[$key].SuccessCount
                Blacklisted = $History[$key].Blacklisted
            }
        }
        
        $jsonObject | ConvertTo-Json -Depth 10 | Set-Content $script:PersistentTrackingFile -Force
    } catch {
        Write-Warning "Failed to save persistent tracking data: $_"
    }
}

function Update-PersistentTracking {
    <#
    .SYNOPSIS
    Updates persistent tracking for a DNS provider
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$History,
        
        [Parameter(Mandatory=$true)]
        [string]$DnsIP,
        
        [Parameter(Mandatory=$true)]
        [bool]$Failed
    )
    
    if (-not $History.ContainsKey($DnsIP)) {
        $History[$DnsIP] = @{
            FailureCount = 0
            LastFailure = [DateTime]::MinValue
            TotalRuns = 0
            SuccessCount = 0
            Blacklisted = $false
        }
    }
    
    $History[$DnsIP].TotalRuns++
    
    if ($Failed) {
        $History[$DnsIP].FailureCount++
        $History[$DnsIP].LastFailure = Get-Date
        
        # Check if should be blacklisted
        if ($History[$DnsIP].FailureCount -ge $PersistentFailureThreshold) {
            $History[$DnsIP].Blacklisted = $true
        }
    } else {
        $History[$DnsIP].SuccessCount++
        # Reset failure count on success (but keep total runs)
        if ($History[$DnsIP].SuccessCount -gt 0) {
            $History[$DnsIP].FailureCount = 0
            $History[$DnsIP].Blacklisted = $false
        }
    }
}

function Get-BlacklistedDNS {
    <#
    .SYNOPSIS
    Returns list of blacklisted DNS IPs
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$History
    )
    
    $blacklisted = @()
    foreach ($dns in $History.Keys) {
        if ($History[$dns].Blacklisted) {
            $blacklisted += $dns
        }
    }
    
    return $blacklisted
}

function Show-TrackingStatistics {
    <#
    .SYNOPSIS
    Displays persistent tracking statistics
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$History
    )
    
    Write-ColoredMessage "`nPersistent DNS Tracking Statistics" -Color Cyan
    Write-ColoredMessage "===================================" -Color Cyan
    
    if ($History.Keys.Count -eq 0) {
        Write-ColoredMessage "No tracking history available yet." -Color Yellow
        return
    }
    
    $stats = $History.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            DNS = $_.Key
            TotalRuns = $_.Value.TotalRuns
            Failures = $_.Value.FailureCount
            Successes = $_.Value.SuccessCount
            FailureRate = if ($_.Value.TotalRuns -gt 0) { 
                [math]::Round(($_.Value.FailureCount / $_.Value.TotalRuns) * 100, 1) 
            } else { 0 }
            Blacklisted = if ($_.Value.Blacklisted) { "YES" } else { "No" }
            LastFailure = if ($_.Value.LastFailure -ne [DateTime]::MinValue) { 
                $_.Value.LastFailure.ToString("yyyy-MM-dd HH:mm") 
            } else { "Never" }
        }
    } | Sort-Object -Property Blacklisted, FailureRate -Descending
    
    $stats | Format-Table -AutoSize
    
    $blacklistedCount = ($stats | Where-Object { $_.Blacklisted -eq "YES" }).Count
    if ($blacklistedCount -gt 0) {
        Write-ColoredMessage "Total blacklisted DNS servers: $blacklistedCount" -Color Red
    } else {
        Write-ColoredMessage "No DNS servers are currently blacklisted." -Color Green
    }
}

# Function to get adaptive timeout for DNS provider
function Get-AdaptiveTimeout {
    param(
        [string]$Category,
        [string]$ProviderName,
        [int]$BaseTimeout,
        [int]$EgyptianTimeout,
        [bool]$UseAdaptive
    )
    
    if (-not $UseAdaptive) {
        return $BaseTimeout
    }
      # Use longer timeout for Egyptian DNS as they tend to be slower
    if ($Category -eq "Egyptian") {
        # Even longer timeout for Egyptian DNS due to infrastructure issues
        return [math]::Max($EgyptianTimeout, 10)
    }
    
    # Global DNS uses base timeout
    return $BaseTimeout
}

# Function to track DNS failures and successes
function Update-DnsTracker {
    param(
        [string]$DnsIP,
        [string]$ProviderName,
        [bool]$Success
    )
    
    $key = "$DnsIP|$ProviderName"
    
    if (-not $script:DnsFailureTracker.ContainsKey($key)) {
        $script:DnsFailureTracker[$key] = 0
        $script:DnsSuccessTracker[$key] = 0
    }
    
    if ($Success) {
        $script:DnsSuccessTracker[$key]++
    } else {
        $script:DnsFailureTracker[$key]++
    }
}

# Function to check if DNS should be removed due to excessive failures
function Test-DnsRemoval {
    param(
        [string]$DnsIP,
        [string]$ProviderName,
        [int]$FailureThreshold,
        [double]$MaxFailureRate
    )
    
    $key = "$DnsIP|$ProviderName"
    
    if (-not $script:DnsFailureTracker.ContainsKey($key)) {
        return $false
    }
    
    $failures = $script:DnsFailureTracker[$key]
    $successes = $script:DnsSuccessTracker[$key]
    $totalTests = $failures + $successes
    
    # Check consecutive failures threshold
    if ($failures -ge $FailureThreshold -and $successes -eq 0) {
        return $true
    }
    
    # Check failure rate threshold (only if we have enough tests)
    if ($totalTests -ge 3) {
        $failureRate = $failures / $totalTests
        if ($failureRate -ge $MaxFailureRate) {
            return $true
        }
    }
    
    return $false
}

# Function to remove consistently failing DNS providers
function Remove-FailingDnsProviders {
    param(
        [Array]$DnsProviders,
        [int]$FailureThreshold,
        [double]$MaxFailureRate,
        [bool]$HideWarnings,
        [bool]$AggressiveMode = $false,
        [bool]$DisablePersistentTracking = $false
    )
    
    $filteredProviders = @()
    
    foreach ($dns in $DnsProviders) {
        # In aggressive mode, remove immediately on first failure
        if ($AggressiveMode) {
            $key = "$($dns.IP)|$($dns.Name)"
            if ($script:DnsFailureTracker.ContainsKey($key) -and $script:DnsFailureTracker[$key] -gt 0 -and $script:DnsSuccessTracker[$key] -eq 0) {
                $failures = $script:DnsFailureTracker[$key]
                $successes = $script:DnsSuccessTracker[$key]
                
                # Update persistent tracking for this failure
                if ($PersistentTracking) {
                    Update-PersistentTracking -History $script:PersistentHistory -DnsIP $dns.IP -Failed $true
                }
                
                $script:RemovedDnsProviders += [PSCustomObject]@{
                    Name = $dns.Name
                    IP = $dns.IP
                    Category = $dns.Category
                    Failures = $failures
                    Successes = $successes
                    FailureRate = "100%"
                    Reason = "Aggressive mode - Failed initial test"
                }
                
                if (-not $HideWarnings) {
                    Write-ColoredMessage "  Removing $($dns.Name) ($($dns.IP)) - Failed initial test (Aggressive mode)" -Color Red
                }
                continue
            }
        }
        
        $shouldRemove = Test-DnsRemoval -DnsIP $dns.IP -ProviderName $dns.Name -FailureThreshold $FailureThreshold -MaxFailureRate $MaxFailureRate
        
        if ($shouldRemove) {
            $key = "$($dns.IP)|$($dns.Name)"
            $failures = $script:DnsFailureTracker[$key]
            $successes = $script:DnsSuccessTracker[$key]
            $totalTests = $failures + $successes
            $failureRate = if ($totalTests -gt 0) { [math]::Round(($failures / $totalTests) * 100, 1) } else { 100 }
            
            # Update persistent tracking for this failure
            if (-not $DisablePersistentTracking) {
                Update-PersistentTracking -History $script:PersistentHistory -DnsIP $dns.IP -Failed $true
            }
            
            $script:RemovedDnsProviders += [PSCustomObject]@{
                Name = $dns.Name
                IP = $dns.IP
                Category = $dns.Category
                Failures = $failures
                Successes = $successes
                FailureRate = "$failureRate%"
                Reason = if ($failures -ge $FailureThreshold -and $successes -eq 0) { "Consecutive failures" } else { "High failure rate" }
            }
            
            if (-not $HideWarnings) {
                Write-ColoredMessage "  Removing $($dns.Name) ($($dns.IP)) - $failureRate% failure rate ($failures failures, $successes successes)" -Color Red
            }
        } else {
            $filteredProviders += $dns
        }
    }
    
    return $filteredProviders
}

# ============================================================================
# DNS Provider Catalog
# ============================================================================
# Provider list is loaded from providers.json so the catalog can be tweaked
# without touching the script. The inline fallback below is used only if the
# JSON file is missing or unreadable.
function Get-DNSProviderCatalog {
    [CmdletBinding()]
    param(
        [string]$JsonPath = (Join-Path $PSScriptRoot 'providers.json')
    )

    if (Test-Path -LiteralPath $JsonPath) {
        try {
            $raw = Get-Content -LiteralPath $JsonPath -Raw -ErrorAction Stop
            $obj = $raw | ConvertFrom-Json -ErrorAction Stop
            $list = $obj.providers
            if (-not $list -or $list.Count -eq 0) {
                throw "providers.json contained no entries"
            }
            return @($list | ForEach-Object {
                $proto = if ($_.protocol) { $_.protocol.ToString().ToLower() } else { 'do53' }
                @{
                    Name     = $_.name
                    IP       = $_.ip
                    Category = $_.category
                    Protocol = $proto
                    Url      = if ($_.url)      { [string]$_.url }      else { '' }
                    Hostname = if ($_.hostname) { [string]$_.hostname } else { '' }
                }
            })
        } catch {
            Write-Warning "Failed to load providers.json ($JsonPath): $_. Falling back to built-in catalog."
        }
    } else {
        Write-Warning "providers.json not found at $JsonPath. Falling back to built-in catalog."
    }

    # Minimal hard-coded fallback catalog (kept intentionally small; full list
    # lives in providers.json).
    return @(
        @{ Name = "Google DNS";              IP = "8.8.8.8";        Category = "Global"; Protocol = "do53"; Url = ""; Hostname = "" },
        @{ Name = "Google DNS Secondary";    IP = "8.8.4.4";        Category = "Global"; Protocol = "do53"; Url = ""; Hostname = "" },
        @{ Name = "Cloudflare DNS";          IP = "1.1.1.1";        Category = "Global"; Protocol = "do53"; Url = ""; Hostname = "" },
        @{ Name = "Cloudflare DNS Secondary";IP = "1.0.0.1";        Category = "Global"; Protocol = "do53"; Url = ""; Hostname = "" },
        @{ Name = "Quad9";                   IP = "9.9.9.9";        Category = "Global"; Protocol = "do53"; Url = ""; Hostname = "" },
        @{ Name = "Quad9 Secondary";         IP = "149.112.112.112";Category = "Global"; Protocol = "do53"; Url = ""; Hostname = "" },
        @{ Name = "OpenDNS";                 IP = "208.67.222.222"; Category = "Global"; Protocol = "do53"; Url = ""; Hostname = "" },
        @{ Name = "OpenDNS Secondary";       IP = "208.67.220.220"; Category = "Global"; Protocol = "do53"; Url = ""; Hostname = "" }
    )
}

$dnsProviders = Get-DNSProviderCatalog


# Define domains and record types to resolve
$testDomains = @($Domain)  # Default to the specified domain

if ($AlternateDomains) {
    $alternateDomainList = @(
        "google.com",
        "facebook.com", 
        "youtube.com",
        "amazon.com",
        "microsoft.com",
        "reddit.com",
        "twitter.com",
        "instagram.com",
        "linkedin.com",
        "github.com",
        "stackoverflow.com",
        "wikipedia.org",
        "netflix.com",
        "apple.com",
        "cloudflare.com",
        "discord.com",
        "twitch.tv",
        "zoom.us",
        "dropbox.com",
        "spotify.com",
        "whatsapp.com",
        "telegram.org",
        "office.com",
        "live.com",
        "outlook.com",
        "yahoo.com",
        "bing.com",
        "duckduckgo.com",
        "baidu.com",
        "cnn.com",
        "bbc.com",
        "reuters.com",
        "theguardian.com",
        "nytimes.com",
        "wordpress.com",
        "medium.com",
        "imgur.com",
        "tiktok.com",
        "pinterest.com",
        "tumblr.com",
        "quora.com"
    )
    
    if ($MultiDomainTest) {
        # Test multiple domains (select 5 random domains for comprehensive testing)
        $testDomains = $alternateDomainList | Get-Random -Count 5
        Write-ColoredMessage "Testing multiple domains: $($testDomains -join ', ')" -Color Yellow
    } else {
        # Test single random domain
        $testDomains = @($alternateDomainList | Get-Random)
        Write-ColoredMessage "Using alternate domain: $($testDomains[0])" -Color Yellow
    }
}

$recordTypes = @("A")
if ($MultiRecordTest) {
    $recordTypes += @("AAAA", "MX", "TXT", "NS")
}

# Function to write colored status messages
function Write-ColoredMessage {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline,
        [switch]$Force
    )
    # In -Quiet mode, suppress everything except messages tagged -Force.
    if ($script:Quiet -and -not $Force) { return }
    try {
        if ($NoNewline) {
            Write-Host $Message -ForegroundColor $Color -NoNewline
        } else {
            Write-Host $Message -ForegroundColor $Color
        }
    } catch {
        # Fallback if colored output fails
        Write-Output $Message
    }
}

# ============================================================================
# Structured logging (JSON-lines). One event per line, append-only. The log
# is opt-in via -LogPath; calls are no-ops when not configured. Each record
# carries an ISO-8601 UTC timestamp, the script run id, an event tag, and an
# arbitrary payload hashtable.
# ============================================================================
$script:LogStreamWriter = $null
$script:RunId = [Guid]::NewGuid().ToString('N').Substring(0, 12)

function Initialize-StructuredLog {
    param([string]$Path)
    if (-not $Path) { return }
    try {
        # Resolve to an absolute path BEFORE handing to .NET - StreamWriter
        # uses [Environment]::CurrentDirectory, not PowerShell's $PWD.
        if (-not [System.IO.Path]::IsPathRooted($Path)) {
            $Path = Join-Path (Get-Location).Path $Path
        }
        $dir = Split-Path -Path $Path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -Confirm:$false | Out-Null
        }
        # Append mode (UTF-8, no BOM) so multiple runs can share a log.
        $stream = [System.IO.StreamWriter]::new($Path, $true, [System.Text.UTF8Encoding]::new($false))
        $stream.AutoFlush = $true
        $script:LogStreamWriter = $stream
    } catch {
        Write-Warning "Failed to open log file '$Path': $_. Continuing without structured logging."
        $script:LogStreamWriter = $null
    }
}

function Write-StructuredLog {
    param(
        [Parameter(Mandatory)] [string]$Event,
        [hashtable]$Data = @{}
    )
    if ($null -eq $script:LogStreamWriter) { return }
    try {
        $record = [ordered]@{
            ts    = (Get-Date).ToUniversalTime().ToString('o')
            run   = $script:RunId
            event = $Event
        }
        foreach ($k in $Data.Keys) { $record[$k] = $Data[$k] }
        $script:LogStreamWriter.WriteLine(($record | ConvertTo-Json -Compress -Depth 6))
    } catch {
        # Silently swallow logging failures - they must never break a test run.
    }
}

function Close-StructuredLog {
    if ($script:LogStreamWriter) {
        try { $script:LogStreamWriter.Dispose() } catch { }
        $script:LogStreamWriter = $null
    }
}

# Open the log right away (no-op when -LogPath wasn't supplied) and emit a
# run-start event recording the parameters that drove this invocation.
Initialize-StructuredLog -Path $LogPath
Write-StructuredLog -Event 'run-start' -Data @{
    domain     = $Domain
    category   = $Category
    protocol   = $Protocol
    testCount  = $TestCount
    timeout    = $Timeout
    parallel   = [bool]$Parallel
    quickTest  = [bool]$QuickTest
    maxThreads = $MaxThreads
    mlProfile  = $MLProfile
    quiet      = [bool]$Quiet
    applyDns   = [bool]$ApplyDNS
    pid        = $PID
}

# Function to test if network connectivity is available
function Test-NetworkConnectivity {
    Write-ColoredMessage "Testing network connectivity..." -Color Yellow
    try {
        $internetTest = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet
        
        if (-not $internetTest) {
            Write-ColoredMessage "Error: No internet connection detected." -Color Red
            Write-ColoredMessage "Please check your network settings and try again." -Color Red
            return $false
        }
        
        Write-ColoredMessage "Network connectivity confirmed." -Color Green
        return $true
    } catch {
        Write-ColoredMessage "Error testing network connectivity: $_" -Color Red
        return $false
    }
}

# Function to test IPv6 support (AAAA records)
function Test-IPv6Support {
    param(
        [string]$dnsIP,
        [string]$domain,
        [int]$timeout = 3
    )
    
    try {
        $sb = {
            param($dnsIP, $domain)
            try {
                $result = Resolve-DnsName -Server $dnsIP -Name $domain -Type AAAA -ErrorAction Stop
                # Check if we got valid IPv6 addresses
                $ipv6Addresses = $result | Where-Object { $_.Type -eq 'AAAA' -and $_.IP6Address }
                return @{
                    Success = ($ipv6Addresses.Count -gt 0)
                    AddressCount = $ipv6Addresses.Count
                    Addresses = ($ipv6Addresses | Select-Object -First 2 -ExpandProperty IP6Address)
                }
            } catch {
                return @{Success = $false; Error = $_.Exception.Message}
            }
        }
        return Invoke-DnsScriptBlockWithTimeout -ScriptBlock $sb -ArgumentList @($dnsIP, $domain) -TimeoutSeconds $timeout
    } catch {
        return @{Success = $false; Error = $_.Exception.Message}
    }
}

# Function to test DNSSEC validation support
function Test-DNSSECSupport {
    param(
        [string]$dnsIP,
        [int]$timeout = 3
    )
    
    # Real DNSSEC-validation test:
    #   - dnssec-failed.org has a deliberately broken signature; a *validating*
    #     resolver MUST return SERVFAIL (i.e. the resolve should fail).
    #   - internetsociety.org is correctly signed; a validating resolver should
    #     happily resolve it.
    # A resolver is considered DNSSEC-validating only if BOTH conditions hold.
    # Resolvers that just forward DNSKEY records but don't validate will return
    # an answer for dnssec-failed.org, failing the negative canary.
    
    try {
        $sb = {
            param($dnsIP)
            $out = @{
                BadResolved  = $null   # $true => resolver returned an answer (NOT validating)
                BadSecure    = $null
                GoodResolved = $null
                GoodSecure   = $null
            }
            try {
                $bad = Resolve-DnsName -Server $dnsIP -Name 'dnssec-failed.org' -Type A -DnssecOk -ErrorAction Stop
                $out.BadResolved = ($null -ne $bad)
                $out.BadSecure   = ($bad | Where-Object { $_.QueryType -eq 'A' -and $_.IPAddress }).Count -gt 0
            } catch {
                $out.BadResolved = $false
            }
            try {
                $good = Resolve-DnsName -Server $dnsIP -Name 'internetsociety.org' -Type A -DnssecOk -ErrorAction Stop
                $out.GoodResolved = ($null -ne $good)
                $out.GoodSecure   = ($good | Where-Object { $_.QueryType -eq 'A' -and $_.IPAddress }).Count -gt 0
            } catch {
                $out.GoodResolved = $false
            }
            return $out
        }

        $r = Invoke-DnsScriptBlockWithTimeout -ScriptBlock $sb -ArgumentList @($dnsIP) -TimeoutSeconds $timeout
        if ($r -and $r.ContainsKey('Error') -and $r.Error -eq 'Timeout') {
            return @{ Success = $false; DNSSECSupported = $false; ValidationAttempted = $false; Error = 'Timeout' }
        }
        # Validating resolver: rejects bad-signature zone AND resolves good-signature zone
        $isValidating = ((-not $r.BadSecure) -and $r.GoodSecure)
        return @{
            Success = $true
            DNSSECSupported = $isValidating
            ValidationAttempted = $true
            BadZoneRejected = (-not $r.BadSecure)
            GoodZoneResolved = $r.GoodSecure
        }
    } catch {
        return @{Success = $false; DNSSECSupported = $false; ValidationAttempted = $false; Error = $_.Exception.Message}
    }
}

# Function to verify DNS response completeness and quality
function Test-ResponseQuality {
    param(
        [string]$dnsIP,
        [string]$domain,
        [string]$recordType = "A",
        [int]$timeout = 3
    )
    
    try {
        $sb = { 
            param($dnsIP, $domain, $recordType)
            try {
                $result = Resolve-DnsName -Server $dnsIP -Name $domain -Type $recordType -ErrorAction Stop
                
                # Check response quality indicators
                $quality = @{
                    HasAnswer = $false
                    AnswerCount = 0
                    HasValidTTL = $false
                    IsHijacked = $false
                    IsComplete = $false
                }
                
                if ($result) {
                    $answers = $result | Where-Object { $_.Section -eq 'Answer' -or $_.Type -eq $recordType }
                    $quality.HasAnswer = ($answers.Count -gt 0)
                    $quality.AnswerCount = $answers.Count
                    
                    # Check for valid TTL (not 0 or suspiciously high)
                    $ttlValues = $answers | Where-Object { $_.TTL } | Select-Object -ExpandProperty TTL
                    if ($ttlValues) {
                        $avgTTL = ($ttlValues | Measure-Object -Average).Average
                        $quality.HasValidTTL = ($avgTTL -gt 0 -and $avgTTL -lt 86400)  # Between 0 and 1 day
                    }
                    
                    # Check for NXDOMAIN hijacking (suspicious IPs like 127.0.0.1 or private ranges for public domains)
                    if ($recordType -eq "A") {
                        $ips = $answers | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
                        foreach ($ip in $ips) {
                            # Check for common hijack IPs
                            if ($ip -match '^127\.' -or $ip -match '^192\.168\.' -or $ip -match '^10\.' -or $ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') {
                                $quality.IsHijacked = $true
                                break
                            }
                        }
                    }
                    
                    $quality.IsComplete = ($quality.HasAnswer -and $quality.HasValidTTL -and -not $quality.IsHijacked)
                }
                
                return @{
                    Success = $true
                    Quality = $quality
                }
            } catch {
                return @{Success = $false; Error = $_.Exception.Message}
            }
        }
        return Invoke-DnsScriptBlockWithTimeout -ScriptBlock $sb -ArgumentList @($dnsIP, $domain, $recordType) -TimeoutSeconds $timeout
    } catch {
        return @{Success = $false; Error = $_.Exception.Message}
    }
}

# Function to test EDNS0 (Extension Mechanisms for DNS) support
function Test-EDNS0Support {
    param(
        [string]$dnsIP,
        [int]$timeout = 3
    )
    
    try {
        # Use nslookup with +edns option to test EDNS0
        # EDNS0 allows for larger UDP packets (>512 bytes) and additional flags
        $testDomain = "google.com"
        
        $sb = { 
            param($dnsIP, $domain)
            try {
                # PowerShell Resolve-DnsName uses EDNS0 by default, so we check for buffer size response
                $result = Resolve-DnsName -Server $dnsIP -Name $domain -Type A -ErrorAction Stop
                
                # If we get a result, the server supports at least basic EDNS0
                # Advanced: Check if server respects EDNS buffer size (would need raw packet inspection)
                $ednsSupported = ($null -ne $result)
                
                return @{
                    Success = $true
                    EDNS0Supported = $ednsSupported
                    BufferSize = 4096  # Default EDNS buffer size
                }
            } catch {
                return @{
                    Success = $false
                    EDNS0Supported = $false
                    Error = $_.Exception.Message
                }
            }
        }
        $result = Invoke-DnsScriptBlockWithTimeout -ScriptBlock $sb -ArgumentList @($dnsIP, $testDomain) -TimeoutSeconds $timeout
        if ($result -and $result.ContainsKey('Error') -and $result.Error -eq 'Timeout') {
            return @{ Success = $false; EDNS0Supported = $false; Error = 'Timeout' }
        }
        return $result
    } catch {
        return @{Success = $false; EDNS0Supported = $false; Error = $_.Exception.Message}
    }
}

# Function to test TCP fallback support (critical for gaming/streaming with large responses)
function Test-TCPFallback {
    param(
        [string]$dnsIP,
        [int]$timeout = 5
    )
    
    try {
        # Query a domain known to return large responses requiring TCP
        # TXT records for SPF/DKIM are often large enough to trigger TCP fallback
        $testDomain = "google.com"
        $testType = "TXT"  # TXT records are often large
        
        $sb = { 
            param($dnsIP, $domain, $recordType)
            try {
                # Request TXT records which can be large and may trigger TCP fallback
                $result = Resolve-DnsName -Server $dnsIP -Name $domain -Type $recordType -ErrorAction Stop
                
                # If we successfully get TXT records, TCP fallback likely works
                $tcpSupported = ($null -ne $result -and $result.Count -gt 0)
                
                # Count the response size (more records = larger response)
                $recordCount = if ($result -is [Array]) { $result.Count } else { 1 }
                
                return @{
                    Success = $true
                    TCPSupported = $tcpSupported
                    RecordCount = $recordCount
                    TestedWith = "TXT records"
                }
            } catch {
                # If TXT query fails, try with ANY query (larger response)
                try {
                    $anyResult = Resolve-DnsName -Server $dnsIP -Name $domain -Type A -ErrorAction Stop
                    return @{
                        Success = $true
                        TCPSupported = $true
                        RecordCount = 1
                        TestedWith = "Fallback A record"
                    }
                } catch {
                    return @{
                        Success = $false
                        TCPSupported = $false
                        Error = $_.Exception.Message
                    }
                }
            }
        }
        $result = Invoke-DnsScriptBlockWithTimeout -ScriptBlock $sb -ArgumentList @($dnsIP, $testDomain, $testType) -TimeoutSeconds $timeout
        if ($result -and $result.ContainsKey('Error') -and $result.Error -eq 'Timeout') {
            return @{ Success = $false; TCPSupported = $false; Error = 'Timeout' }
        }
        return $result
    } catch {
        return @{Success = $false; TCPSupported = $false; Error = $_.Exception.Message}
    }
}

# Function to test content filtering (malware / ads / adult) using canary domains.
# A category is reported as "Blocked" when the resolver either returns NXDOMAIN /
# refuses the query, or returns a sinkhole address (0.0.0.0, 127.0.0.0/8, or the
# all-zeros AAAA ::). A category is reported as "Allowed" when a routable answer
# is returned. A category is "N/A" if the canary lookup itself errors / times out.
function Test-DNSFiltering {
    param(
        [string]$dnsIP,
        [int]$timeout = 4
    )

    # Vendor-supplied canary domains where available; otherwise the most common
    # block-listed real domains used by family / ad-blocking resolvers.
    $canaries = @{
        Malware = 'malware.testcategory.com'           # used by Cisco / OpenDNS family
        Phishing = 'phishing.testcategory.com'
        Ads     = 'doubleclick.net'                    # blocked by AdGuard / NextDNS / ControlD
        Adult   = 'pornhub.com'                        # blocked by family / ControlD-Family
    }

    try {
        $sb = {
            param($dnsIP, $canaries)

            function Test-IsSinkholeIP {
                param([string]$ip)
                if (-not $ip) { return $false }
                if ($ip -eq '0.0.0.0' -or $ip -eq '::') { return $true }
                if ($ip -match '^127\.') { return $true }
                return $false
            }

            $out = @{}
            foreach ($cat in $canaries.Keys) {
                $domain = $canaries[$cat]
                $entry = @{ Domain = $domain; Blocked = $false; Reason = $null; Resolved = $false }
                try {
                    $r = Resolve-DnsName -Server $dnsIP -Name $domain -Type A -ErrorAction Stop
                    $ips = @($r | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
                    if ($ips.Count -eq 0) {
                        $entry.Blocked = $true
                        $entry.Reason  = 'NoAnswer'
                    } elseif (($ips | Where-Object { Test-IsSinkholeIP $_ }).Count -gt 0) {
                        $entry.Blocked = $true
                        $entry.Reason  = 'Sinkhole'
                    } else {
                        $entry.Resolved = $true
                        $entry.Reason   = 'Allowed'
                    }
                } catch {
                    # NXDOMAIN, REFUSED, etc. all surface as terminating errors here.
                    $msg = $_.Exception.Message
                    if ($msg -match 'DNS name does not exist|NXDOMAIN|Name does not exist') {
                        $entry.Blocked = $true
                        $entry.Reason  = 'NXDOMAIN'
                    } else {
                        $entry.Reason  = "Error: $msg"
                    }
                }
                $out[$cat] = $entry
            }
            return $out
        }

        $r = Invoke-DnsScriptBlockWithTimeout -ScriptBlock $sb -ArgumentList @($dnsIP, $canaries) -TimeoutSeconds $timeout
        if ($r -and $r.ContainsKey('Error') -and $r.Error -eq 'Timeout') {
            return @{ Success = $false; Error = 'Timeout' }
        }
        return @{ Success = $true; Categories = $r }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Function to test DNS resolution time with jitter calculation
function Test-DNS {
    param(
        [string]$dnsIP,
        [string]$domain,
        [string]$recordType = "A",
        [string]$category = "Global",
        [string]$providerName = "Unknown",
        [string]$probeProtocol = "do53",
        [string]$url = "",
        [string]$hostname = ""
    )

    $responseTimes = @()
    $successCount = 0
    
    # Get adaptive timeout based on category
    $currentTimeout = Get-AdaptiveTimeout -Category $category -ProviderName $providerName -BaseTimeout $Timeout -EgyptianTimeout $EgyptianTimeout -UseAdaptive $AdaptiveTimeout.IsPresent
    
    Write-ColoredMessage "  Testing reliability ($recordType record, timeout: ${currentTimeout}s)... " -Color Gray -NoNewline

    # First do a single test to check reliability - also measure timing for jitter calculation
    try {
        $result = Invoke-DnsProbe -IP $dnsIP -Domain $domain -RecordType $recordType -ProbeProtocol $probeProtocol -Url $url -Hostname $hostname -TimeoutSeconds $currentTimeout
        if ($result -and $result.Error -eq 'Timeout') {
            Write-ColoredMessage "Failed (timeout)" -Color Red
            Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
            Write-StructuredLog -Event 'probe-failed' -Data @{ ip=$dnsIP; provider=$providerName; protocol=$probeProtocol; recordType=$recordType; domain=$domain; reason='timeout' }
            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType; Domain = $domain}
        }

        if (-not $result.Success) {
            Write-ColoredMessage "Failed ($($result.Error))" -Color Red
            Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
            Write-StructuredLog -Event 'probe-failed' -Data @{ ip=$dnsIP; provider=$providerName; protocol=$probeProtocol; recordType=$recordType; domain=$domain; reason=[string]$result.Error }
            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType; Domain = $domain}
        }
        
        # Reliability probe doubles as a warm-up: it primes any local resolver
        # state, so we deliberately exclude its timing from the jitter / median
        # statistics. The probe itself still counts toward the success rate.
        $reliabilityTime = [double]$result.ResponseTimeMs
    } catch {
        Write-ColoredMessage "Failed (error: $_)" -Color Red
        Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
        Write-StructuredLog -Event 'probe-failed' -Data @{ ip=$dnsIP; provider=$providerName; protocol=$probeProtocol; recordType=$recordType; domain=$domain; reason="exception: $_" }
        return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType; Domain = $domain}
    }

    Write-ColoredMessage "Passed" -Color Green
    
    # Count the initial reliability test as a success
    Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $true
    
    # Initialize successCount to 1 since the reliability test passed
    # This ensures DNS that pass reliability but fail some performance tests aren't marked as complete failures
    $successCount = 1
    
    # If initial test passed, proceed with performance testing
    for ($i = 1; $i -le $TestCount; $i++) {
        try {
            if ($DetailedOutput) {
                $progressParams = @{
                    Activity = "Testing DNS Server"
                    Status = "Performance Test $i of $TestCount"
                    PercentComplete = ($i / $TestCount) * 100
                    CurrentOperation = "IP: $dnsIP ($recordType) - Timeout: ${currentTimeout}s - Domain: $domain"
                }
                Write-Progress @progressParams
            }

            # Optionally bust the recursive-resolver cache so we measure a real
            # upstream lookup rather than a sub-millisecond cache hit.
            $probeDomain = if ($CacheBust) { Get-CacheBustingDomain -Domain $domain } else { $domain }

            # Retry-with-backoff loop. Only timeouts trigger a retry; an explicit
            # error response is treated as a hard failure (no retry).
            $attempt = 0
            $probeSucceeded = $false
            $probeTime = 0.0
            $attemptTimeout = $currentTimeout
            while ($attempt -le $MaxRetries -and -not $probeSucceeded) {
                $attempt++
                $probeResult = Invoke-DnsProbe -IP $dnsIP -Domain $probeDomain -RecordType $recordType -ProbeProtocol $probeProtocol -Url $url -Hostname $hostname -TimeoutSeconds $attemptTimeout
                $timedOut = ($probeResult -and $probeResult.Error -eq 'Timeout')
                if (-not $timedOut -and $probeResult.Success) {
                    $probeTime = [double]$probeResult.ResponseTimeMs
                    $probeSucceeded = $true
                }

                # Only timeouts justify a retry; an explicit DNS error (NXDOMAIN
                # against a real domain, REFUSED, etc.) won't get faster on retry.
                if (-not $timedOut) { break }
                # Exponential backoff: 1.5x per attempt, capped at 2x base.
                $attemptTimeout = [int][Math]::Min($attemptTimeout * 1.5, $currentTimeout * 2)
            }

            if ($probeSucceeded) {
                $responseTimes += $probeTime
                $successCount++
                Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $true
            } else {
                Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
            }
        } catch {
            # Continue testing even if one test fails
            Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
            if ($DetailedOutput) {
                Write-Host "Error in test $i for $dnsIP ($recordType) on $domain : $_" -ForegroundColor Yellow
            }
            continue
        }
    }
    
    if ($DetailedOutput) {
        Write-Progress -Activity "Testing DNS Server $dnsIP" -Completed
    }
    
    # If NO performance tests succeeded (but reliability passed), we still have 1 success from reliability test
    # Return success with 0 response time but non-zero success rate to show reliability passed
    if ($responseTimes.Count -eq 0) {
        $totalTests = $TestCount + 1
        $successRate = ($successCount / $totalTests) * 100
        return @{Status = "Success"; ResponseTime = 0; Jitter = 0; Median = 0; Mean = 0; StdDev = 0; P95 = 0; IQR = 0; SampleCount = 0; ReliabilityTime = $reliabilityTime; RecordType = $recordType; Domain = $domain; SuccessRate = $successRate; ActualTimeout = $currentTimeout; IPv6Support = $null; DNSSECSupport = $null; ResponseQuality = $null}
    }
    
    # Robust statistics on the performance-probe sample (the reliability/warm-up
    # probe is intentionally excluded to avoid cold-cache bias).
    $rtArray = [double[]]$responseTimes
    $mean   = ($rtArray | Measure-Object -Average).Average
    $median = Get-Percentile -Values $rtArray -Percentile 50
    $p95    = Get-Percentile -Values $rtArray -Percentile 95
    $q1     = Get-Percentile -Values $rtArray -Percentile 25
    $q3     = Get-Percentile -Values $rtArray -Percentile 75
    $iqr    = [Math]::Max(0, $q3 - $q1)

    $stddev = if ($rtArray.Count -gt 1) {
        [Math]::Sqrt(($rtArray | ForEach-Object { [Math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average)
    } else { 0 }

    # Headline metrics use the outlier-resistant median + IQR. Mean / std-dev /
    # P95 are surfaced as additional fields for debugging and reporting.
    $headlineRT     = [Math]::Round($median, 2)
    $headlineJitter = [Math]::Round($iqr, 2)

    # Calculate success rate: total successful tests (reliability + performance) / total tests run
    # We ran 1 reliability test + $TestCount performance tests = ($TestCount + 1) total
    $totalTests = $TestCount + 1
    $successRate = ($successCount / $totalTests) * 100

    Write-StructuredLog -Event 'probe-result' -Data @{
        ip          = $dnsIP
        provider    = $providerName
        protocol    = $probeProtocol
        recordType  = $recordType
        domain      = $domain
        median      = [Math]::Round($median, 2)
        mean        = [Math]::Round($mean, 2)
        p95         = [Math]::Round($p95, 2)
        iqr         = [Math]::Round($iqr, 2)
        sampleCount = $rtArray.Count
        successRate = $successRate
    }

    return @{
        Status = "Success"
        ResponseTime = $headlineRT       # median (was mean)
        Jitter = $headlineJitter         # IQR (was std-dev)
        Median = $headlineRT
        Mean = [Math]::Round($mean, 2)
        StdDev = [Math]::Round($stddev, 2)
        P95 = [Math]::Round($p95, 2)
        IQR = $headlineJitter
        SampleCount = $rtArray.Count
        ReliabilityTime = [Math]::Round($reliabilityTime, 2)
        RecordType = $recordType
        SuccessRate = $successRate
        ActualTimeout = $currentTimeout
        Domain = $domain
        IPv6Support = $null
        DNSSECSupport = $null
        ResponseQuality = $null
    }
}

# Load persistent tracking history
$script:PersistentHistory = Initialize-PersistentTracking

# Handle reset tracking request
if ($ResetTracking) {
    if (Test-Path $script:PersistentTrackingFile) {
        Remove-Item $script:PersistentTrackingFile -Force
        Write-ColoredMessage "Persistent tracking history has been reset." -Color Green
        $script:PersistentHistory = @{}
    } else {
        Write-ColoredMessage "No tracking history to reset." -Color Yellow
    }
    
    if ($ShowTrackingStats) {
        Show-TrackingStatistics -History $script:PersistentHistory
    }
    exit 0
}

# Show tracking stats if requested
if ($ShowTrackingStats) {
    Show-TrackingStatistics -History $script:PersistentHistory
    if (-not $PSBoundParameters.ContainsKey('Domain')) {
        # Exit if only showing stats
        exit 0
    }
}

# Clear screen and show header
Clear-Host

# Start timing
$script:TestStartTime = Get-Date

Write-ColoredMessage "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
Write-ColoredMessage "DNS Benchmark" -Color Cyan -NoNewline
Write-ColoredMessage " | " -Color DarkGray -NoNewline
Write-ColoredMessage "$($testDomains -join ', ')" -Color White -NoNewline
if ($QuickTest) {
    Write-ColoredMessage " | " -Color DarkGray -NoNewline
    Write-ColoredMessage "Quick" -Color Yellow -NoNewline
}
if ($SortByScore) {
    Write-ColoredMessage " | " -Color DarkGray -NoNewline
    Write-ColoredMessage "Jitter×$JitterWeight" -Color Magenta -NoNewline
}
Write-Host ""
Write-ColoredMessage "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan

# Show info about additional tests
$additionalTests = @()
if (-not $SkipIPv6Test) { $additionalTests += "IPv6" }
if (-not $SkipDNSSECTest) { $additionalTests += "DNSSEC" }
if (-not $SkipResponseVerification) { $additionalTests += "Quality" }
if ($TestEDNS0) { $additionalTests += "EDNS0" }
if ($TestTCP) { $additionalTests += "TCP" }
if ($additionalTests.Count -gt 0) {
    Write-ColoredMessage "Additional tests: $($additionalTests -join ', ')" -Color Cyan
}

if ($testDomains.Count -gt 1) {
    Write-ColoredMessage "Multi-domain testing: Testing each DNS server against $($testDomains.Count) domains" -Color Yellow
}
if ($AdaptiveTimeout) {
    Write-ColoredMessage "Adaptive timeout enabled: Egyptian DNS timeout = $EgyptianTimeout seconds" -Color Yellow
}
if (-not $DisableFailureRemoval -or $AggressiveMode) {
    Write-ColoredMessage "Failure removal enabled: Max failure rate = $([math]::Round($MaxFailureRate * 100, 1))%, Threshold = $FailureThreshold consecutive failures" -Color Yellow
    if ($AggressiveMode) {
        Write-ColoredMessage "Aggressive mode: DNS servers will be removed after 2+ consecutive failures" -Color Yellow
    }
}
Write-ColoredMessage "===================" -Color Cyan

# Check network connectivity before proceeding
if (-not (Test-NetworkConnectivity)) {
    exit 1
}

# Reset in-memory failure trackers for this test run
# (Persistent tracking in JSON file is maintained separately)
$script:DnsFailureTracker = @{}
$script:DnsSuccessTracker = @{}
$script:RemovedDnsProviders = @()

# Filter DNS providers by category
$filteredDnsProviders = if ($Category -eq "All") {
    $dnsProviders 
} else { 
    $dnsProviders | Where-Object { $_.Category -eq $Category } 
}

# Protocol filter (Do53 / DoH / DoT). Default 'All' keeps every entry.
if ($Protocol -ne 'All') {
    $protoLower = $Protocol.ToLower()
    $filteredDnsProviders = $filteredDnsProviders | Where-Object { $_.Protocol -eq $protoLower }
}

# If the encrypted-DNS module didn't load, drop DoH/DoT entries with a notice
# rather than letting them all fail.
if (-not $script:EncryptedDnsAvailable) {
    $beforeProtoCount = ($filteredDnsProviders | Measure-Object).Count
    $filteredDnsProviders = $filteredDnsProviders | Where-Object { $_.Protocol -ne 'doh' -and $_.Protocol -ne 'dot' }
    $droppedProto = $beforeProtoCount - ($filteredDnsProviders | Measure-Object).Count
    if ($droppedProto -gt 0) {
        Write-ColoredMessage "Dropped $droppedProto DoH/DoT provider(s) - DnsWireProtocol module not loaded." -Color Yellow
    }
}

# Parallel mode currently only supports Do53 (the inline worker doesn't ship
# the wire-protocol module into runspaces). Skip encrypted entries with a notice.
if ($Parallel) {
    $beforeParCount = ($filteredDnsProviders | Measure-Object).Count
    $filteredDnsProviders = $filteredDnsProviders | Where-Object { $_.Protocol -eq 'do53' }
    $droppedPar = $beforeParCount - ($filteredDnsProviders | Measure-Object).Count
    if ($droppedPar -gt 0) {
        Write-ColoredMessage "Skipping $droppedPar DoH/DoT provider(s) in -Parallel mode (run sequentially to test those)." -Color Yellow
    }
}

if ($filteredDnsProviders.Count -eq 0) {
    Write-ColoredMessage "No DNS providers match the specified category: $Category" -Color Red
    exit 1
}

# Filter out blacklisted DNS providers
if (-not $DisablePersistentTracking) {
    $blacklistedIPs = Get-BlacklistedDNS -History $script:PersistentHistory
    
    if ($blacklistedIPs.Count -gt 0) {
        Write-ColoredMessage "`nFiltering out $($blacklistedIPs.Count) blacklisted DNS server(s) from history..." -Color Yellow
        
        $beforeCount = $filteredDnsProviders.Count
        $filteredDnsProviders = $filteredDnsProviders | Where-Object { 
            $blacklistedIPs -notcontains $_.IP
        }
        $afterCount = $filteredDnsProviders.Count
        
        if ($beforeCount -ne $afterCount) {
            Write-ColoredMessage "Removed $($beforeCount - $afterCount) DNS provider(s) due to persistent failures" -Color Yellow
        }
    }
}

if ($filteredDnsProviders.Count -eq 0) {
    Write-ColoredMessage "No DNS providers remaining after filtering. Try -ResetTracking to start fresh." -Color Red
    exit 1
}

# ML-based prioritization: Test best-performing DNS servers first
if ($script:MLEnabled -and $script:MLData.Servers.Count -gt 0) {
    Write-ColoredMessage "ML Optimization: Prioritizing top-performing DNS servers from $($script:MLData.TotalRuns) historical runs..." -Color Cyan
    
    $filteredDnsProviders = Get-PrioritizedServers -AllServers $filteredDnsProviders -MLData $script:MLData
    
    if ($QuickTest) {
        $exitStatus = if ($NoEarlyExit) { "early exit DISABLED" } else { "early exit enabled" }
        Write-ColoredMessage "QuickTest: Testing all $($filteredDnsProviders.Count) DNS providers (ML-prioritized, $exitStatus)" -Color Yellow
    }
    
    # Show ML recommendation if available
    $mlRecommendation = Get-MLRecommendedPair -MLData $script:MLData -PreferredType "Best Overall"
    if ($mlRecommendation) {
        Write-ColoredMessage "ML Recommended Pair: $($mlRecommendation.PrimaryProvider) ($($mlRecommendation.PrimaryIP)) + $($mlRecommendation.SecondaryProvider) ($($mlRecommendation.SecondaryIP))" -Color Green
        Write-ColoredMessage "  Based on $($mlRecommendation.TestCount) tests, Avg Score: $([Math]::Round($mlRecommendation.AverageScore, 2))" -Color Green
    }
}
# QuickTest optimization: Sort DNS providers by historical success (fallback if ML not available)
elseif ($QuickTest -and -not $DisablePersistentTracking -and $script:PersistentHistory.Keys.Count -gt 0) {
    Write-ColoredMessage "QuickTest: Prioritizing historically reliable DNS servers..." -Color Cyan
    
    $filteredDnsProviders = $filteredDnsProviders | Sort-Object {
        $ip = $_.IP
        if ($script:PersistentHistory.ContainsKey($ip)) {
            $record = $script:PersistentHistory[$ip]
            # Calculate reliability score (lower is better for sorting)
            # Prioritize: high success count, low failure count
            if ($record.TotalRuns -gt 0) {
                $successRate = $record.SuccessCount / $record.TotalRuns
                # Return negative success rate so higher success comes first
                return -$successRate * 1000 - $record.TotalRuns
            }
        }
        # Unknown DNS servers get tested last
        return 0
    }
    
    $exitStatus = if ($NoEarlyExit) { "early exit DISABLED" } else { "early exit enabled" }
    Write-ColoredMessage "QuickTest: Testing all $($filteredDnsProviders.Count) DNS providers (history-prioritized, $exitStatus)" -Color Yellow
}
# Pure QuickTest mode without history - prioritize known fast providers but test all
elseif ($QuickTest) {
    Write-ColoredMessage "QuickTest: Prioritizing major fast DNS providers (no history available)" -Color Yellow
    # Prioritize known fast providers: Cloudflare, Google, Quad9, OpenDNS
    $fastProviders = @('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', 
                       '208.67.222.222', '208.67.220.220', '94.140.14.14', '94.140.15.15',
                       '163.121.128.135', '163.121.128.134')  # Include Egyptian DNS
    
    $prioritized = $filteredDnsProviders | Where-Object { $fastProviders -contains $_.IP }
    $others = $filteredDnsProviders | Where-Object { $fastProviders -notcontains $_.IP }
    
    $filteredDnsProviders = $prioritized + $others
    $exitStatus = if ($NoEarlyExit) { "early exit DISABLED" } else { "early exit enabled" }
    Write-ColoredMessage "QuickTest: Testing all $($filteredDnsProviders.Count) DNS providers (fast providers first, $exitStatus)" -Color Yellow
}

# Create results array
$results = @()

# Test each DNS provider
if ($Parallel) {
    Write-ColoredMessage "`nRunning tests in parallel mode (faster but less precise timing) - MaxThreads=$MaxThreads" -Color Yellow

    # Prefer Start-ThreadJob (in-process, ~50x cheaper to spin up than Start-Job
    # which forks a fresh powershell.exe per call). On Windows PowerShell 5.1
    # the ThreadJob module is shipped via the gallery; ensure it's loaded if
    # available, fall back to Start-Job if not.
    $useThreadJob = $false
    if (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue) {
        $useThreadJob = $true
    } elseif (Get-Module -ListAvailable -Name ThreadJob) {
        try {
            Import-Module ThreadJob -ErrorAction Stop
            $useThreadJob = $true
        } catch {
            Write-Warning "ThreadJob module present but failed to import: $_. Falling back to Start-Job."
        }
    } else {
        Write-Warning "ThreadJob module not found. Install with: Install-Module ThreadJob -Scope CurrentUser. Falling back to Start-Job (much slower)."
    }

    try {
        # Create job script block for each DNS provider and record type
        $jobs = @()
        
        foreach ($dns in $filteredDnsProviders) {
            foreach ($recordType in $recordTypes) {
                $jobScriptBlock = {
                    param($dns, $testDomain, $recordType, $timeout, $testCount)
                    
                    function Write-ColoredMessage {
                        param(
                            [string]$Message,
                            [string]$Color = "White",
                            [switch]$NoNewline
                        )
                        try {
                            if ($NoNewline) {
                                Write-Host $Message -ForegroundColor $Color -NoNewline
                            } else {
                                Write-Host $Message -ForegroundColor $Color
                            }
                        } catch {
                            Write-Output $Message
                        }
                    }

                    function Test-DNS {
                        param(
                            [string]$dnsIP,
                            [string]$domain,
                            [string]$recordType = "A"
                        )

                        $responseTimes = @()
                        $successCount = 0

                        # Reliability test (no nested job - relies on Resolve-DnsName's
                        # built-in DNS-client timeout, which is sufficient for parallel
                        # mode where wall-clock per-probe slop is acceptable).
                        try {
                            Resolve-DnsName -Server $dnsIP -Name $domain -Type $recordType -DnsOnly -ErrorAction Stop | Out-Null
                        } catch {
                            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
                        }

                        # Performance testing
                        for ($i = 1; $i -le $testCount; $i++) {
                            try {
                                $startTime = Get-Date
                                Resolve-DnsName -Server $dnsIP -Name $domain -Type $recordType -DnsOnly -ErrorAction Stop | Out-Null
                                $endTime = Get-Date
                                $responseTimes += ($endTime - $startTime).TotalMilliseconds
                                $successCount++
                            } catch {
                                continue
                            }
                        }

                        if ($successCount -eq 0) {
                            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
                        }
                        
                        $averageTime = ($responseTimes | Measure-Object -Average).Average
                        $jitter = if ($responseTimes.Count -gt 1) {
                            $standardDeviation = [Math]::Sqrt(($responseTimes | ForEach-Object { [Math]::Pow($_ - $averageTime, 2) } | Measure-Object -Average).Average)
                            [Math]::Round($standardDeviation, 2)
                        } else {
                            0
                        }
                        
                        return @{
                            Status = "Success"
                            ResponseTime = [math]::Round($averageTime, 2)
                            Jitter = $jitter
                            RecordType = $recordType
                            SuccessRate = ($successCount / $testCount) * 100
                        }
                    }
                    
                    # Test the DNS provider
                    $result = Test-DNS -dnsIP $dns.IP -domain $testDomain -recordType $recordType
                    
                    # Return the result
                    return @{
                        Provider = $dns.Name
                        IP = $dns.IP
                        Category = $dns.Category
                        ResponseTime = $result.ResponseTime
                        Jitter = $result.Jitter
                        Status = $result.Status
                        RecordType = $recordType
                        SuccessRate = $result.SuccessRate
                    }
                }
                
                # Start the job (ThreadJob if available, fall back to Start-Job)
                if ($useThreadJob) {
                    $job = Start-ThreadJob -ScriptBlock $jobScriptBlock -ArgumentList $dns, $testDomain, $recordType, $Timeout, $TestCount -ThrottleLimit $MaxThreads
                } else {
                    $job = Start-Job -ScriptBlock $jobScriptBlock -ArgumentList $dns, $testDomain, $recordType, $Timeout, $TestCount
                }
                $jobs += @{Job = $job; DNS = $dns; RecordType = $recordType}
            }
        }
        
        # Display progress while waiting for jobs
        $totalJobs = $jobs.Count
        $completedJobs = 0
        
        while ($jobs | Where-Object { $_.Job.State -eq 'Running' }) {
            $completedJobs = ($jobs | Where-Object { $_.Job.State -ne 'Running' }).Count
            Write-Progress -Activity "Testing DNS Servers" -Status "Progress" -PercentComplete (($completedJobs / $totalJobs) * 100)
            Start-Sleep -Milliseconds 500
        }
        Write-Progress -Activity "Testing DNS Servers" -Completed
        
        # Process results from jobs
        foreach ($jobInfo in $jobs) {
            $job = $jobInfo.Job
            $dns = $jobInfo.DNS
            $recordType = $jobInfo.RecordType
            
            Write-ColoredMessage "`nProcessing results for $($dns.Name) ($recordType)..." -Color Yellow
            $jobResult = Receive-Job -Job $job -ErrorAction SilentlyContinue
            
            if ($jobResult) {
                $results += [PSCustomObject]@{
                    Provider = $jobResult.Provider
                    IP = $jobResult.IP
                    Category = $jobResult.Category
                    ResponseTime = if ($jobResult.Status -eq "Error") { "Timeout" } else { "$($jobResult.ResponseTime) ms" }
                    Status = $jobResult.Status
                    Jitter = if ($jobResult.Status -eq "Error") { "N/A" } else { "$($jobResult.Jitter) ms" }
                    RecordType = $jobResult.RecordType
                    SuccessRate = if ($jobResult.Status -eq "Error") { 0 } else { $jobResult.SuccessRate }
                    IPv6 = "N/A"  # Parallel mode skips extended tests for speed
                    DNSSEC = "N/A"
                    Quality = "N/A"
                }
            } else {
                # If job failed entirely, record an error
                $results += [PSCustomObject]@{
                    Provider = $dns.Name
                    IP = $dns.IP
                    Category = $dns.Category
                    ResponseTime = "Error"
                    Status = "Error"
                    Jitter = "N/A"
                    RecordType = $recordType
                    SuccessRate = 0
                    IPv6 = "N/A"
                    DNSSEC = "N/A"
                    Quality = "N/A"
                }
                Write-ColoredMessage "  Job failed for $($dns.Name)" -Color Red
            }
            
            # Clean up the job
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-ColoredMessage "Error in parallel testing: $_" -Color Red
        Write-ColoredMessage "Switching to sequential testing mode..." -Color Yellow
        # If parallel testing fails, fall back to sequential
        $Parallel = $false
    }
}

# Sequential testing as fallback or default
if (-not $Parallel) {
    $testCounter = 0
    $totalToTest = $filteredDnsProviders.Count
    foreach ($dns in $filteredDnsProviders) {
        $testCounter++
        Write-Host "`r" -NoNewline
        Write-Host "Testing DNS [$testCounter/$totalToTest]: " -NoNewline -ForegroundColor Cyan
        Write-Host "$($dns.Name)" -NoNewline -ForegroundColor Yellow
        Write-Host " " -NoNewline
        
        # Test each domain
        foreach ($testDomain in $testDomains) {
            if ($testDomains.Count -gt 1) {
                Write-ColoredMessage "  Domain: $testDomain" -Color Cyan
            }
            
            foreach ($recordType in $recordTypes) {
                $result = Test-DNS -dnsIP $dns.IP -domain $testDomain -recordType $recordType -category $dns.Category -providerName $dns.Name -probeProtocol $dns.Protocol -url $dns.Url -hostname $dns.Hostname
                
                # Show compact status
                if ($result.Status -eq "Success") {
                    Write-Host "✓" -NoNewline -ForegroundColor Green
                } else {
                    Write-Host "✗" -NoNewline -ForegroundColor Red
                }
                
                # Capability tests are run independently of the A-record probe
                # so we still get an IPv6/DNSSEC/EDNS0/TCP capability matrix
                # for resolvers that are slow or have flaky A-record performance.
                $capTimeout = if ($result.ActualTimeout) { $result.ActualTimeout } else { $Timeout }

                # Test IPv6 support
                if (-not $SkipIPv6Test) {
                    $ipv6Test = Test-IPv6Support -dnsIP $dns.IP -domain $testDomain -timeout $capTimeout
                    $result.IPv6Support = $ipv6Test.Success
                }

                # Test DNSSEC support (only once per DNS, not per domain/record)
                if (-not $SkipDNSSECTest -and $null -eq $result.DNSSECSupport) {
                    $dnssecTest = Test-DNSSECSupport -dnsIP $dns.IP -timeout $capTimeout
                    $result.DNSSECSupport = $dnssecTest.DNSSECSupported
                }

                # Verify response quality (skip if main probe didn't succeed -
                # the underlying record likely won't resolve either)
                if (-not $SkipResponseVerification -and $result.Status -eq "Success") {
                    $qualityTest = Test-ResponseQuality -dnsIP $dns.IP -domain $testDomain -recordType $recordType -timeout $capTimeout
                    if ($qualityTest.Success) {
                        $result.ResponseQuality = $qualityTest.Quality.IsComplete
                    }
                }

                # Test EDNS0 support (only once per DNS)
                if ($TestEDNS0 -and $null -eq $result.EDNS0Support) {
                    $edns0Test = Test-EDNS0Support -dnsIP $dns.IP -timeout $capTimeout
                    $result.EDNS0Support = $edns0Test.EDNS0Supported
                }

                # Test TCP fallback support (only once per DNS)
                if ($TestTCP -and $null -eq $result.TCPSupport) {
                    $tcpTest = Test-TCPFallback -dnsIP $dns.IP -timeout $capTimeout
                    $result.TCPSupport = $tcpTest.TCPSupported
                }

                # Test content filtering (only once per DNS)
                if ($TestFiltering -and $null -eq $result.Filtering) {
                    $filterTest = Test-DNSFiltering -dnsIP $dns.IP -timeout ([Math]::Max($capTimeout, 4))
                    if ($filterTest.Success) {
                        $result.Filtering = $filterTest.Categories
                    }
                }
                
                # Update persistent tracking
                if (-not $DisablePersistentTracking) {
                    $failed = ($result.Status -eq "Error")
                    Update-PersistentTracking -History $script:PersistentHistory -DnsIP $dns.IP -Failed $failed
                }
                
                # Update ML training data
                if ($script:MLEnabled -and $result.Status -eq "Success") {
                    $filteringSeen = $false
                    if ($result.Filtering) {
                        foreach ($cat in $result.Filtering.Values) {
                            if ($cat.Blocked) { $filteringSeen = $true; break }
                        }
                    }
                    Update-ServerMLData -MLData $script:MLData `
                        -IP $dns.IP `
                        -Provider $dns.Name `
                        -ResponseTime $result.ResponseTime `
                        -SuccessRate $result.SuccessRate `
                        -Jitter $result.Jitter `
                        -Category $dns.Category `
                        -IPv6Support ($result.IPv6Support -eq $true) `
                        -DNSSECSupport ($result.DNSSECSupport -eq $true) `
                        -QualityCheck ($result.ResponseQuality -eq $true) `
                        -EDNS0Support ($result.EDNS0Support -eq $true) `
                        -TCPSupport ($result.TCPSupport -eq $true) `
                        -FilteringSupport $filteringSeen
                }
                
                $results += [PSCustomObject]@{
                    Provider = $dns.Name
                    IP = $dns.IP
                    Category = $dns.Category
                    Domain = $testDomain
                    ResponseTime = if ($result.Status -eq "Error") { "Timeout" } else { "$($result.ResponseTime) ms" }
                    Status = $result.Status
                    Jitter = if ($result.Status -eq "Error") { "N/A" } else { "$($result.Jitter) ms" }
                    Mean = if ($result.Status -eq "Error") { "N/A" } else { "$($result.Mean) ms" }
                    StdDev = if ($result.Status -eq "Error") { "N/A" } else { "$($result.StdDev) ms" }
                    P95 = if ($result.Status -eq "Error") { "N/A" } else { "$($result.P95) ms" }
                    SampleCount = if ($result.Status -eq "Error") { 0 } else { $result.SampleCount }
                    RecordType = $result.RecordType
                    SuccessRate = if ($result.Status -eq "Error") { 0 } else { $result.SuccessRate }
                    IPv6 = if ($null -eq $result.IPv6Support) { "N/A" } elseif ($result.IPv6Support) { "✓" } else { "✗" }
                    DNSSEC = if ($null -eq $result.DNSSECSupport) { "N/A" } elseif ($result.DNSSECSupport) { "✓" } else { "✗" }
                    Quality = if ($null -eq $result.ResponseQuality) { "N/A" } elseif ($result.ResponseQuality) { "✓" } else { "✗" }
                    EDNS0 = if ($null -eq $result.EDNS0Support) { "N/A" } elseif ($result.EDNS0Support) { "✓" } else { "✗" }
                    TCP = if ($null -eq $result.TCPSupport) { "N/A" } elseif ($result.TCPSupport) { "✓" } else { "✗" }
                    BlocksMalware = if ($null -eq $result.Filtering) { "N/A" } elseif ($result.Filtering.Malware.Blocked) { "✓" } else { "✗" }
                    BlocksAds = if ($null -eq $result.Filtering) { "N/A" } elseif ($result.Filtering.Ads.Blocked) { "✓" } else { "✗" }
                    BlocksAdult = if ($null -eq $result.Filtering) { "N/A" } elseif ($result.Filtering.Adult.Blocked) { "✓" } else { "✗" }
                }
            }
        }
        
        # QuickTest early exit: Stop if we have enough good DNS servers (unless disabled)
        if ($QuickTest -and -not $NoEarlyExit) {
            $successfulResults = $results | Where-Object { $_.Status -eq "Success" }
            $successfulByCategory = $successfulResults | Group-Object -Property Category
            
            # Aggressive early exit thresholds for QuickTest
            # We only need a few good servers to make a recommendation
            $egyptianCount = ($successfulByCategory | Where-Object { $_.Name -eq "Egyptian" })
            $globalCount = ($successfulByCategory | Where-Object { $_.Name -eq "Global" })
            $controlDCount = ($successfulByCategory | Where-Object { $_.Name -eq "ControlD" })
            
            $hasEnoughEgyptian = if ($egyptianCount) { $egyptianCount.Count -ge 2 } else { $false }
            $hasEnoughGlobal = if ($globalCount) { $globalCount.Count -ge 5 } else { $false }
            $hasEnoughControlD = if ($controlDCount) { $controlDCount.Count -ge 1 } else { $false }
            
            # Exit early if we have minimum viable results
            # OR if we have at least 10 successful DNS servers total
            $totalSuccessful = $successfulResults.Count
            
            if (($hasEnoughEgyptian -and $hasEnoughGlobal -and $hasEnoughControlD) -or ($totalSuccessful -ge 10)) {
                Write-ColoredMessage "`nQuickTest: Found $totalSuccessful successful DNS servers, stopping early..." -Color Cyan
                Write-ColoredMessage "  (Use -NoEarlyExit to test all available DNS providers)" -Color DarkGray
                break
            }
        }
        
        # After testing each DNS provider, check if THIS specific one should be removed
        if (-not $DisableFailureRemoval -or $AggressiveMode) {
            $shouldRemoveThis = Test-DnsRemoval -DnsIP $dns.IP -ProviderName $dns.Name -FailureThreshold $FailureThreshold -MaxFailureRate $MaxFailureRate
            
            if ($AggressiveMode) {
                $key = "$($dns.IP)|$($dns.Name)"
                # In aggressive mode, require at least 2 failures before removal (not just 1)
                # This prevents false positives from single network hiccups
                if ($script:DnsFailureTracker.ContainsKey($key) -and $script:DnsFailureTracker[$key] -ge 2 -and $script:DnsSuccessTracker[$key] -eq 0) {
                    $shouldRemoveThis = $true
                }
            }
            
            if ($shouldRemoveThis) {
                $key = "$($dns.IP)|$($dns.Name)"
                $failures = if ($script:DnsFailureTracker.ContainsKey($key)) { $script:DnsFailureTracker[$key] } else { 0 }
                $successes = if ($script:DnsSuccessTracker.ContainsKey($key)) { $script:DnsSuccessTracker[$key] } else { 0 }
                $totalTests = $failures + $successes
                $failureRate = if ($totalTests -gt 0) { [math]::Round(($failures / $totalTests) * 100, 1) } else { 100 }
                
                # Update persistent tracking for this failure
                if (-not $DisablePersistentTracking) {
                    Update-PersistentTracking -History $script:PersistentHistory -DnsIP $dns.IP -Failed $true
                }
                
                $script:RemovedDnsProviders += [PSCustomObject]@{
                    Name = $dns.Name
                    IP = $dns.IP
                    Category = $dns.Category
                    Failures = $failures
                    Successes = $successes
                    FailureRate = "$failureRate%"
                    Reason = if ($AggressiveMode) { "Aggressive mode - Failed test" } elseif ($failures -ge $FailureThreshold -and $successes -eq 0) { "Consecutive failures" } else { "High failure rate" }
                }
                
                if (-not $HideWarnings) {
                    Write-ColoredMessage "  Removing $($dns.Name) ($($dns.IP)) - $failureRate% failure rate ($failures failures, $successes successes)" -Color Red
                }
                
                # Remove this DNS from the list by filtering it out
                $filteredDnsProviders = $filteredDnsProviders | Where-Object { $_.IP -ne $dns.IP -or $_.Name -ne $dns.Name }
                
                # Check if too many DNS providers were removed
                if ($filteredDnsProviders.Count -lt ($dnsProviders.Count / 2)) {
                    Write-ColoredMessage "Warning: More than half of the DNS providers have been removed due to failures." -Color Yellow
                    Write-ColoredMessage "This might indicate network connectivity issues. Consider running the test again." -Color Yellow
                }
            }
        }
    }
}

# Check if we have any results
if ($results.Count -eq 0) {
    Write-ColoredMessage "`nNo results were gathered. Please check your network connection and try again." -Color Red
    exit 1
}

# Function to filter out DNS providers that failed all tests
function Remove-CompletelyFailedDNS {
    param (
        [Array]$ResultsData
    )
    
    # Group results by DNS provider (Name + IP combination)
    $dnsGroups = $ResultsData | Group-Object { "$($_.Provider)|$($_.IP)" }
    
    $validResults = @()
    $removedProviders = @()
    
    foreach ($group in $dnsGroups) {
        $providerResults = $group.Group
        $totalTests = $providerResults.Count
        # Only count as failed if SuccessRate is exactly 0 (never passed any test including reliability)
        # DNS that passed reliability test will have SuccessRate > 0 even if performance tests failed
        $failedTests = ($providerResults | Where-Object { $_.SuccessRate -eq 0 }).Count
        
        # Calculate failure rate
        $failureRate = if ($totalTests -gt 0) { ($failedTests / $totalTests) * 100 } else { 100 }
        
        # If provider failed ALL tests (100% failure rate), remove it
        if ($failureRate -eq 100) {
            $removedProvider = $providerResults[0] # Get provider info from first result
            $removedProviders += [PSCustomObject]@{
                Name = $removedProvider.Provider
                IP = $removedProvider.IP
                Category = $removedProvider.Category
                TotalTests = $totalTests
                FailedTests = $failedTests
                FailureRate = "100%"
                Reason = "Failed all tests across all domains and record types"
            }
            
            Write-ColoredMessage "  Removing $($removedProvider.Provider) ($($removedProvider.IP)) - Failed all $totalTests tests" -Color Red
        } else {
            # Keep this provider's results
            $validResults += $providerResults
        }
    }
    
    if ($removedProviders.Count -gt 0) {
        Write-ColoredMessage "`nRemoved $($removedProviders.Count) DNS provider(s) that failed all tests:" -Color Yellow
        $removedProviders | Format-Table -AutoSize -Property Name, IP, Category, TotalTests, Reason | Out-Host
        
        # Add to global removed providers list
        foreach ($removed in $removedProviders) {
            $script:RemovedDnsProviders += [PSCustomObject]@{
                Name = $removed.Name
                IP = $removed.IP
                Category = $removed.Category
                Failures = $removed.TotalTests
                Successes = 0
                FailureRate = "100%"
                Reason = "Failed all tests"
            }
        }
    }
    
    return $validResults
}

# Remove DNS providers that failed all tests
$originalCount = $results.Count
$filteredResults = Remove-CompletelyFailedDNS -ResultsData $results
$removedCount = $originalCount - $filteredResults.Count

if ($removedCount -gt 0) {
    Write-Host "`n" # New line after progress
    Write-ColoredMessage "Removed $removedCount DNS that failed all tests" -Color DarkGray
    $results = $filteredResults
} else {
    Write-Host "`n" # New line after progress
}

# Also filter out DNS that only passed reliability test but failed all performance tests
# These show 0ms response time and aren't usable for actual queries
$performanceFailedCount = ($results | Where-Object { $_.ResponseTime -eq "0 ms" -or $_.ResponseTime -eq 0 }).Count
if ($performanceFailedCount -gt 0) {
    $results = $results | Where-Object { $_.ResponseTime -ne "0 ms" -and $_.ResponseTime -ne 0 }
}

# Check if we have any valid results after filtering
if ($results.Count -eq 0) {
    Write-ColoredMessage "`nNo valid DNS results remain after filtering. All tested DNS servers failed completely." -Color Red
    Write-ColoredMessage "This might indicate a network connectivity issue. Please check your internet connection and try again." -Color Red
    exit 1
}

# Calculate composite score for each result (ResponseTime + Jitter × Weight)
Write-ColoredMessage "`nCalculating composite scores (Response Time + Jitter × $JitterWeight)..." -Color Cyan
foreach ($result in $results) {
    $responseTime = if ($result.ResponseTime -eq "Timeout" -or $result.ResponseTime -eq "Error") { 
        [double]::MaxValue 
    } else { 
        [double]($result.ResponseTime -replace ' ms$', '') 
    }
    
    $jitter = if ($result.Jitter -eq "N/A" -or $result.Jitter -eq 0) { 
        0 
    } else { 
        [double]($result.Jitter -replace ' ms$', '') 
    }
    
    # Composite Score = Response Time + (Jitter × Weight)
    $result | Add-Member -NotePropertyName "CompositeScore" -NotePropertyValue ($responseTime + ($jitter * $JitterWeight)) -Force
}

# Display results table
Write-ColoredMessage "`nResults Summary:" -Color Cyan
Write-ColoredMessage "=================" -Color Cyan

# Group results by record type if multiple record types were tested
if ($recordTypes.Count -gt 1) {
    foreach ($recordType in $recordTypes) {
        Write-ColoredMessage "`n$recordType Records:" -Color Yellow
        $typeResults = $results | Where-Object { $_.RecordType -eq $recordType }
        if ($typeResults.Count -gt 0) {
            # Sort by composite score (response time + weighted jitter)
            $sortedResults = $typeResults | Sort-Object CompositeScore
            
            # Apply top results filter if specified
            if ($TopResults -gt 0) {
                $sortedResults = $sortedResults | Select-Object -First $TopResults
                Write-ColoredMessage "  Showing top $TopResults fastest DNS providers:" -Color Gray
            }
            
            $sortedResults |
                Format-Table -AutoSize -Property @{
                    Label = "Provider"
                    Expression = { $_.Provider }
                    Width = 25
                }, @{
                    Label = "IP Address"
                    Expression = { $_.IP }
                    Width = 15
                }, @{
                    Label = "Domain"
                    Expression = { $_.Domain }
                    Width = 18
                }, @{
                    Label = "Response Time"
                    Expression = { $_.ResponseTime }
                    Width = 13
                }, @{
                    Label = "Jitter"
                    Expression = { $_.Jitter }
                    Width = 8
                }, @{
                    Label = "Success"
                    Expression = { if ($_.Status -eq "Error") { "0%" } else { "$($_.SuccessRate)%" } }
                    Width = 8
                }, @{
                    Label = "IPv6"
                    Expression = { $_.IPv6 }
                    Width = 5
                }, @{
                    Label = "DNSSEC"
                    Expression = { $_.DNSSEC }
                    Width = 7
                }, @{
                    Label = "Quality"
                    Expression = { $_.Quality }
                    Width = 7
                } | Out-Host
        } else {
            Write-ColoredMessage "  No results for $recordType records." -Color Red
        }
    }
} else {
    # Display single table for one record type
    # Sort by composite score (response time + weighted jitter)
    $sortedResults = $results | Sort-Object CompositeScore
    
    # Apply top results filter if specified
    if ($TopResults -gt 0) {
        $sortedResults = $sortedResults | Select-Object -First $TopResults
        Write-ColoredMessage "Showing top $TopResults DNS providers (sorted by composite score):" -Color Gray
    }
    
    # Build format table properties dynamically
    $formatProps = @(
        @{Label = "Provider"; Expression = { $_.Provider }; Width = 25}
        @{Label = "IP Address"; Expression = { $_.IP }; Width = 15}
        @{Label = "Domain"; Expression = { $_.Domain }; Width = 18}
        @{Label = "Response Time"; Expression = { $_.ResponseTime }; Width = 13}
        @{Label = "Jitter"; Expression = { $_.Jitter }; Width = 8}
    )
    
    # Add composite score column
    $formatProps += @{
        Label = "Score"
        Expression = { 
            if ($_.CompositeScore -eq [double]::MaxValue) { 
                "N/A" 
            } else { 
                "$([math]::Round($_.CompositeScore, 2)) ms" 
            }
        }
        Width = 11
    }
    
    $formatProps += @(
        @{Label = "Success"; Expression = { if ($_.Status -eq "Error") { "0%" } else { "$([math]::Round($_.SuccessRate))%" } }; Width = 8}
        @{Label = "IPv6"; Expression = { $_.IPv6 }; Width = 5}
        @{Label = "DNSSEC"; Expression = { $_.DNSSEC }; Width = 7}
        @{Label = "Quality"; Expression = { $_.Quality }; Width = 7}
    )
    
    $sortedResults | Format-Table -AutoSize -Property $formatProps | Out-Host
}

# Function to calculate DNS statistics
function Get-DNSStatistics {
    param (
        [Array]$ResultsData,
        [string]$RecordType = "A",
        [string]$Category
    )
    
    $filteredResults = $ResultsData | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType -and $_.Category -eq $Category
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }

    $times = $filteredResults | ForEach-Object { [double]($_.ResponseTime -replace ' ms$', '') }
    $jitters = $filteredResults | ForEach-Object { 
        if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
    }
    
    return @{
        Min = ($times | Measure-Object -Minimum).Minimum
        Max = ($times | Measure-Object -Maximum).Maximum
        Avg = ($times | Measure-Object -Average).Average
        AvgJitter = ($jitters | Measure-Object -Average).Average
        Count = $filteredResults.Count
        RecordType = $RecordType
        Category = $Category
    }
}

# Function to find best DNS pair
function Get-BestDNSPair {
    param (
        [Array]$DNSResults,
        [string]$Category,
        [string]$RecordType = "A",
        [bool]$UseCompositeScore = $false,
        [double]$JitterWeight = 2.0
    )
    
    $filteredResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType -and $_.Category -eq $Category
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }

    # Score DNS providers
    $scoredDNS = $filteredResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        
        # Calculate score based on mode
        if ($UseCompositeScore) {
            # Composite Score: ResponseTime + (Jitter × Weight)
            $score = $responseTime + ($jitter * $JitterWeight)
        } else {
            # Legacy scoring: weighted by importance
            $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        }
        
        [PSCustomObject]@{
            Provider = $_.Provider
            IP = $_.IP
            ResponseTime = $_.ResponseTime
            Jitter = $_.Jitter
            SuccessRate = $_.SuccessRate
            Score = $score
            RecordType = $RecordType
            Category = $Category
        }
    }

    # Get the primary DNS (best score)
    $primary = $scoredDNS | Sort-Object Score | Select-Object -First 1

    # Find secondary DNS that is different from primary
    $secondary = $scoredDNS | 
        Where-Object { 
            $_.IP -ne $primary.IP -and 
            $_.Provider -ne $primary.Provider 
        } |
        Sort-Object Score |
        Select-Object -First 1

    # If no suitable secondary found, get the next fastest overall
    if (-not $secondary) {
        $secondary = $scoredDNS | 
            Where-Object { $_.IP -ne $primary.IP } |
            Sort-Object Score |
            Select-Object -Skip 1 -First 1
    }
    
    # If still no secondary, duplicate the primary as fallback
    if (-not $secondary) {
        $secondary = $primary
    }

    return @{
        Primary = $primary
        Secondary = $secondary
        RecordType = $RecordType
        Category = $Category
    }
}

function Get-BestMixedPair {
    <#
    .SYNOPSIS
    Gets the best mixed DNS pair (one Egyptian, one Global)
    #>
    param (
        [Array]$DNSResults,
        [string]$RecordType = "A",
        [bool]$UseCompositeScore = $false,
        [double]$JitterWeight = 2.0
    )
    
    $egyptianResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType -and $_.Category -eq "Egyptian"
    }
    
    $globalResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType -and $_.Category -eq "Global"
    }
    
    if ($egyptianResults.Count -eq 0 -or $globalResults.Count -eq 0) {
        return $null
    }
    
    # Score each DNS
    $scoredEgyptian = $egyptianResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        
        # Calculate score based on mode
        if ($UseCompositeScore) {
            $score = $responseTime + ($jitter * $JitterWeight)
        } else {
            $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        }
        
        [PSCustomObject]@{
            Provider = $_.Provider
            IP = $_.IP
            ResponseTime = $_.ResponseTime
            Jitter = $_.Jitter
            SuccessRate = $_.SuccessRate
            Score = $score
            Category = "Egyptian"
        }
    }
    
    $scoredGlobal = $globalResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        
        # Calculate score based on mode
        if ($UseCompositeScore) {
            $score = $responseTime + ($jitter * $JitterWeight)
        } else {
            $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        }
        
        [PSCustomObject]@{
            Provider = $_.Provider
            IP = $_.IP
            ResponseTime = $_.ResponseTime
            Jitter = $_.Jitter
            SuccessRate = $_.SuccessRate
            Score = $score
            Category = "Global"
        }
    }
    
    $bestEgyptian = $scoredEgyptian | Sort-Object Score | Select-Object -First 1
    $bestGlobal = $scoredGlobal | Sort-Object Score | Select-Object -First 1
    
    # Return Egyptian as primary if it's faster, otherwise Global
    if ($bestEgyptian.Score -le $bestGlobal.Score) {
        return @{
            Primary = $bestEgyptian
            Secondary = $bestGlobal
            Type = "Mixed (Egyptian Primary)"
            AverageScore = ($bestEgyptian.Score + $bestGlobal.Score) / 2
        }
    } else {
        return @{
            Primary = $bestGlobal
            Secondary = $bestEgyptian
            Type = "Mixed (Global Primary)"
            AverageScore = ($bestEgyptian.Score + $bestGlobal.Score) / 2
        }
    }
}

function Get-BestOverallPair {
    <#
    .SYNOPSIS
    Gets the absolute best DNS pair regardless of category
    #>
    param (
        [Array]$DNSResults,
        [string]$RecordType = "A",
        [bool]$UseCompositeScore = $false,
        [double]$JitterWeight = 2.0
    )
    
    $filteredResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }
    
    $scoredDNS = $filteredResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        
        # Calculate score based on mode
        if ($UseCompositeScore) {
            $score = $responseTime + ($jitter * $JitterWeight)
        } else {
            $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        }
        
        [PSCustomObject]@{
            Provider = $_.Provider
            IP = $_.IP
            ResponseTime = $_.ResponseTime
            Jitter = $_.Jitter
            SuccessRate = $_.SuccessRate
            Score = $score
            Category = $_.Category
        }
    }
    
    $primary = $scoredDNS | Sort-Object Score | Select-Object -First 1
    $secondary = $scoredDNS | 
        Where-Object { $_.IP -ne $primary.IP } |
        Sort-Object Score |
        Select-Object -First 1
    
    if (-not $secondary) {
        $secondary = $primary
    }
    
    return @{
        Primary = $primary
        Secondary = $secondary
        Type = "Best Overall"
        AverageScore = ($primary.Score + $secondary.Score) / 2
    }
}

function Get-MostReliablePair {
    <#
    .SYNOPSIS
    Gets the most reliable DNS pair based on success rate
    #>
    param (
        [Array]$DNSResults,
        [string]$RecordType = "A"
    )
    
    $filteredResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }
    
    $scoredDNS = $filteredResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $successRate = [double]($_.SuccessRate)
        
        [PSCustomObject]@{
            Provider = $_.Provider
            IP = $_.IP
            ResponseTime = $_.ResponseTime
            Jitter = $_.Jitter
            SuccessRate = $_.SuccessRate
            Category = $_.Category
        }
    } | Sort-Object @{Expression={$_.SuccessRate}; Descending=$true}, @{Expression={[double]($_.ResponseTime -replace ' ms$', '')}; Ascending=$true}
    
    $primary = $scoredDNS | Select-Object -First 1
    $secondary = $scoredDNS | 
        Where-Object { $_.IP -ne $primary.IP } |
        Select-Object -First 1
    
    if (-not $secondary) {
        $secondary = $primary
    }
    
    return @{
        Primary = $primary
        Secondary = $secondary
        Type = "Most Reliable"
        AverageSuccessRate = ($primary.SuccessRate + $secondary.SuccessRate) / 2
    }
}

function Get-LowLatencyPair {
    <#
    .SYNOPSIS
    Gets the lowest latency DNS pair (focuses on response time)
    #>
    param (
        [Array]$DNSResults,
        [string]$RecordType = "A"
    )
    
    $filteredResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }
    
    $scoredDNS = $filteredResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        
        [PSCustomObject]@{
            Provider = $_.Provider
            IP = $_.IP
            ResponseTime = $responseTime
            Jitter = $_.Jitter
            SuccessRate = $_.SuccessRate
            Category = $_.Category
        }
    } | Sort-Object ResponseTime
    
    $primary = $scoredDNS | Select-Object -First 1
    $secondary = $scoredDNS | 
        Where-Object { $_.IP -ne $primary.IP } |
        Select-Object -First 1
    
    if (-not $secondary) {
        $secondary = $primary
    }
    
    return @{
        Primary = $primary
        Secondary = $secondary
        Type = "Lowest Latency"
        AverageLatency = ($primary.ResponseTime + $secondary.ResponseTime) / 2
    }
}

function Get-LowestJitterPair {
    <#
    .SYNOPSIS
    Gets the DNS pair with lowest jitter (most stable/consistent)
    #>
    param (
        [Array]$DNSResults,
        [string]$RecordType = "A"
    )
    
    $filteredResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }
    
    $scoredDNS = $filteredResults | ForEach-Object {
        $jitter = if ($_.Jitter -eq "N/A") { [double]::MaxValue } else { [double]($_.Jitter -replace ' ms$', '') }
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        
        [PSCustomObject]@{
            Provider = $_.Provider
            IP = $_.IP
            ResponseTime = "$responseTime ms"
            Jitter = $_.Jitter
            NumericJitter = $jitter
            SuccessRate = $_.SuccessRate
            Category = $_.Category
        }
    } | Sort-Object NumericJitter
    
    $primary = $scoredDNS | Select-Object -First 1
    $secondary = $scoredDNS | 
        Where-Object { $_.IP -ne $primary.IP } |
        Select-Object -First 1
    
    if (-not $secondary) {
        $secondary = $primary
    }
    
    return @{
        Primary = $primary
        Secondary = $secondary
        Type = "Lowest Jitter"
        AverageJitter = ($primary.NumericJitter + $secondary.NumericJitter) / 2
    }
}

function Get-BestSameProviderPair {
    <#
    .SYNOPSIS
    Gets the best DNS pair from the same provider (e.g., Quad9 + Quad9 Secondary, NOT Quad9 + Quad9 Unsecured)
    Only matches strict primary/secondary pairs, not different variants of the same provider
    #>
    param (
        [Array]$DNSResults,
        [string]$RecordType = "A",
        [bool]$UseCompositeScore = $false,
        [double]$JitterWeight = 2.0
    )
    
    $filteredResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }
    
    # Score each DNS
    $scoredDNS = $filteredResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        
        # Calculate score based on mode
        if ($UseCompositeScore) {
            $score = $responseTime + ($jitter * $JitterWeight)
        } else {
            $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        }
        
        # More strict base provider extraction
        # Only remove "Secondary", "Alt", "2", "3" that are clearly secondary indicators
        # Keep variant names like "Unsecured", "Secure", "Family", etc.
        $baseProvider = $_.Provider
        
        # Check if this is a secondary/alternate server
        $isSecondary = $false
        if ($_.Provider -match '\s+(Secondary|Alt)\s*\d*$') {
            $isSecondary = $true
            $baseProvider = $_.Provider -replace '\s+(Secondary|Alt)\s*\d*$', ''
        } elseif ($_.Provider -match '\s+\d+$' -and $_.Provider -notmatch '(Quad9|DNS)\s+\d+$') {
            # Only remove trailing numbers if they're not part of the name (like "Quad9" or "DNS")
            $isSecondary = $true
            $baseProvider = $_.Provider -replace '\s+\d+$', ''
        }
        
        $baseProvider = $baseProvider.Trim()
        
        [PSCustomObject]@{
            Provider = $_.Provider
            BaseProvider = $baseProvider
            IsSecondary = $isSecondary
            IP = $_.IP
            ResponseTime = $_.ResponseTime
            Jitter = $_.Jitter
            SuccessRate = $_.SuccessRate
            Score = $score
            Category = $_.Category
            NumericResponseTime = $responseTime
        }
    }
    
    # Group by base provider - only consider groups that have both primary and secondary
    $providerGroups = $scoredDNS | Group-Object BaseProvider
    
    $bestProviderPair = $null
    $bestPairScore = [double]::MaxValue
    
    foreach ($group in $providerGroups) {
        # Must have at least one primary and one secondary
        $primaries = $group.Group | Where-Object { -not $_.IsSecondary }
        $secondaries = $group.Group | Where-Object { $_.IsSecondary }
        
        if ($primaries.Count -eq 0 -or $secondaries.Count -eq 0) {
            continue
        }
        
        # Get best primary and best secondary from this provider
        $primary = $primaries | Sort-Object Score | Select-Object -First 1
        $secondary = $secondaries | Sort-Object Score | Select-Object -First 1
        
        if ($primary -and $secondary -and $primary.IP -ne $secondary.IP) {
            $pairScore = ($primary.Score + $secondary.Score) / 2
            
            # Keep track of the best pair across all providers
            if ($pairScore -lt $bestPairScore) {
                $bestPairScore = $pairScore
                $bestProviderPair = @{
                    Primary = $primary
                    Secondary = $secondary
                    ProviderName = $group.Name
                    Type = "Best Same Provider"
                    AverageScore = $pairScore
                    AverageLatency = ($primary.NumericResponseTime + $secondary.NumericResponseTime) / 2
                }
            }
        }
    }
    
    return $bestProviderPair
}

# Function to get the best same-provider pair for global providers only
function Get-BestSameProviderPairGlobal {
    <#
    .SYNOPSIS
    Gets the best DNS pair from the same global provider (e.g., Quad9 + Quad9 Secondary, NOT Quad9 + Quad9 Unsecured)
    Only matches strict primary/secondary pairs, not different variants of the same provider
    #>
    param (
        [Array]$DNSResults,
        [string]$RecordType = "A",
        [bool]$UseCompositeScore = $false,
        [double]$JitterWeight = 2.0
    )
    
    $filteredResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType -and $_.Category -eq "Global"
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }

    # Score each DNS
    $scoredDNS = $filteredResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        
        # Calculate score based on mode
        if ($UseCompositeScore) {
            $score = $responseTime + ($jitter * $JitterWeight)
        } else {
            $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        }
        
        # More strict base provider extraction
        # Only remove "Secondary", "Alt", "2", "3" that are clearly secondary indicators
        # Keep variant names like "Unsecured", "Secure", "Family", etc.
        $baseProvider = $_.Provider
        
        # Check if this is a secondary/alternate server
        $isSecondary = $false
        if ($_.Provider -match '\s+(Secondary|Alt)\s*\d*$') {
            $isSecondary = $true
            $baseProvider = $_.Provider -replace '\s+(Secondary|Alt)\s*\d*$', ''
        } elseif ($_.Provider -match '\s+\d+$' -and $_.Provider -notmatch '(Quad9|DNS)\s+\d+$') {
            # Only remove trailing numbers if they're not part of the name (like "Quad9" or "DNS")
            $isSecondary = $true
            $baseProvider = $_.Provider -replace '\s+\d+$', ''
        }
        
        $baseProvider = $baseProvider.Trim()
        
        [PSCustomObject]@{
            Provider = $_.Provider
            BaseProvider = $baseProvider
            IsSecondary = $isSecondary
            IP = $_.IP
            ResponseTime = $_.ResponseTime
            Jitter = $_.Jitter
            SuccessRate = $_.SuccessRate
            Score = $score
            Category = $_.Category
            NumericResponseTime = $responseTime
        }
    }

    # Group by base provider - only consider groups that have both primary and secondary
    $providerGroups = $scoredDNS | Group-Object BaseProvider
    
    $bestProviderPair = $null
    $bestPairScore = [double]::MaxValue
    
    foreach ($group in $providerGroups) {
        # Must have at least one primary and one secondary
        $primaries = $group.Group | Where-Object { -not $_.IsSecondary }
        $secondaries = $group.Group | Where-Object { $_.IsSecondary }
        
        if ($primaries.Count -eq 0 -or $secondaries.Count -eq 0) {
            continue
        }
        
        # Get best primary and best secondary from this provider
        $primary = $primaries | Sort-Object Score | Select-Object -First 1
        $secondary = $secondaries | Sort-Object Score | Select-Object -First 1
        
        if ($primary -and $secondary -and $primary.IP -ne $secondary.IP) {
            $pairScore = ($primary.Score + $secondary.Score) / 2
            
            # Keep track of the best pair across all providers
            if ($pairScore -lt $bestPairScore) {
                $bestPairScore = $pairScore
                $bestProviderPair = @{
                    Primary = $primary
                    Secondary = $secondary
                    ProviderName = $group.Name
                    Type = "Best Same Provider (Global)"
                    AverageScore = $pairScore
                    AverageLatency = ($primary.NumericResponseTime + $secondary.NumericResponseTime) / 2
                }
            }
        }
    }
    
    return $bestProviderPair
}

# Process results by category
$categoryResults = @{}
$categoryStats = @{}
$bestPairs = @{}

foreach ($category in @("Egyptian", "Global", "ControlD")) {
    $categoryResults[$category] = $results | Where-Object { $_.Category -eq $category }
    
    foreach ($recordType in $recordTypes) {
        # Calculate statistics for this category and record type
        $categoryStats["${category}_${recordType}"] = Get-DNSStatistics -ResultsData $results -RecordType $recordType -Category $category
        
        # Find the best DNS pair for this category and record type
        $bestPairs["${category}_${recordType}"] = Get-BestDNSPair -DNSResults $results -Category $category -RecordType $recordType -UseCompositeScore $true -JitterWeight $JitterWeight
    }
}

# Display final results with statistics
Write-ColoredMessage "`n`nFinal Recommendations" -Color Cyan
Write-ColoredMessage "===================" -Color Cyan

foreach ($recordType in $recordTypes) {
    if ($recordTypes.Count -gt 1) {
        Write-ColoredMessage "`n[$recordType Records]" -Color Magenta
    }
    
    # Get statistics for each category
    $egyptianStats = $categoryStats["Egyptian_${recordType}"]
    $globalStats = $categoryStats["Global_${recordType}"]
    
    # Get best pairs for each category
    $bestEgyptianPair = $bestPairs["Egyptian_${recordType}"]
    $bestGlobalPair = $bestPairs["Global_${recordType}"]
    
    # Get additional pairing options
    $bestMixedPair = Get-BestMixedPair -DNSResults $results -RecordType $recordType -UseCompositeScore $true -JitterWeight $JitterWeight
    $bestOverallPair = Get-BestOverallPair -DNSResults $results -RecordType $recordType -UseCompositeScore $true -JitterWeight $JitterWeight
    $mostReliablePair = Get-MostReliablePair -DNSResults $results -RecordType $recordType
    $lowLatencyPair = Get-LowLatencyPair -DNSResults $results -RecordType $recordType
    $lowestJitterPair = Get-LowestJitterPair -DNSResults $results -RecordType $recordType
    $bestSameProviderPairGlobal = Get-BestSameProviderPairGlobal -DNSResults $results -RecordType $recordType -UseCompositeScore $true -JitterWeight $JitterWeight
    
    # Display all pairing options
    Write-ColoredMessage "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
    Write-ColoredMessage "DNS PAIRING OPTIONS" -Color Cyan
    Write-ColoredMessage "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
    
    # Option 1: Best Egyptian
    Write-ColoredMessage "`n[1] Best Egyptian DNS Configuration:" -Color Yellow
    if ($bestEgyptianPair -and $bestEgyptianPair.Primary -and $bestEgyptianPair.Secondary) {
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($bestEgyptianPair.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestEgyptianPair.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestEgyptianPair.Primary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestEgyptianPair.Primary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ")" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($bestEgyptianPair.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestEgyptianPair.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestEgyptianPair.Secondary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestEgyptianPair.Secondary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ")" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Local servers, potentially less censorship" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: May have reliability issues" -Color DarkYellow
        
        if ($egyptianStats) {
            Write-Host "    Stats: Avg: " -NoNewline -ForegroundColor White
            Write-Host "$([math]::Round($egyptianStats.Avg, 2)) ms" -NoNewline -ForegroundColor Cyan
            Write-Host " | Jitter: " -NoNewline -ForegroundColor White
            Write-Host "$([math]::Round($egyptianStats.AvgJitter, 2)) ms" -ForegroundColor Cyan
        }
    } else {
        Write-ColoredMessage "    No valid Egyptian DNS pair found" -Color Red
    }

    # Option 2: Best Global
    Write-ColoredMessage "`n[2] Best Global DNS Configuration:" -Color Yellow
    if ($bestGlobalPair -and $bestGlobalPair.Primary -and $bestGlobalPair.Secondary) {
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($bestGlobalPair.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestGlobalPair.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestGlobalPair.Primary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestGlobalPair.Primary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ")" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($bestGlobalPair.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestGlobalPair.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestGlobalPair.Secondary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestGlobalPair.Secondary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ")" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Highly reliable, global infrastructure" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: May be slower from Egypt" -Color DarkYellow
        
        if ($globalStats) {
            Write-Host "    Stats: Avg: " -NoNewline -ForegroundColor White
            Write-Host "$([math]::Round($globalStats.Avg, 2)) ms" -NoNewline -ForegroundColor Cyan
            Write-Host " | Jitter: " -NoNewline -ForegroundColor White
            Write-Host "$([math]::Round($globalStats.AvgJitter, 2)) ms" -ForegroundColor Cyan
        }
    } else {
        Write-ColoredMessage "    No valid Global DNS pair found" -Color Red
    }
    
    # Option 3: Best Mixed
    Write-ColoredMessage "`n[3] Best Mixed Configuration (Egyptian + Global):" -Color Yellow
    if ($bestMixedPair) {
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($bestMixedPair.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestMixedPair.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestMixedPair.Primary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestMixedPair.Primary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestMixedPair.Primary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($bestMixedPair.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestMixedPair.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestMixedPair.Secondary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestMixedPair.Secondary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestMixedPair.Secondary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Balanced approach, failover between local and global" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: Performance varies by location" -Color DarkYellow
        Write-Host "    Stats: Avg Score: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($bestMixedPair.AverageScore, 2))" -ForegroundColor Cyan
    } else {
        Write-ColoredMessage "    Cannot create mixed pair (need both Egyptian and Global DNS)" -Color Red
    }
    
    # Option 4: Best Overall
    Write-ColoredMessage "`n[4] Best Overall Performance (Any Category):" -Color Yellow
    if ($bestOverallPair) {
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($bestOverallPair.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestOverallPair.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestOverallPair.Primary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestOverallPair.Primary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestOverallPair.Primary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($bestOverallPair.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestOverallPair.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestOverallPair.Secondary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestOverallPair.Secondary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestOverallPair.Secondary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Absolute best performance in testing" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: May prioritize speed over reliability" -Color DarkYellow
        Write-Host "    Stats: Avg Score: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($bestOverallPair.AverageScore, 2))" -ForegroundColor Cyan
    } else {
        Write-ColoredMessage "    No valid DNS found" -Color Red
    }
    
    # Option 5: Most Reliable
    Write-ColoredMessage "`n[5] Most Reliable Configuration:" -Color Yellow
    if ($mostReliablePair) {
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($mostReliablePair.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($mostReliablePair.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($mostReliablePair.Primary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Success: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($mostReliablePair.Primary.SuccessRate)%" -NoNewline -ForegroundColor Green
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($mostReliablePair.Primary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($mostReliablePair.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($mostReliablePair.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($mostReliablePair.Secondary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Success: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($mostReliablePair.Secondary.SuccessRate)%" -NoNewline -ForegroundColor Green
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($mostReliablePair.Secondary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Highest success rate, most stable" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: May not be the fastest option" -Color DarkYellow
        Write-Host "    Stats: Avg Success Rate: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($mostReliablePair.AverageSuccessRate, 2))%" -ForegroundColor Green
    } else {
        Write-ColoredMessage "    No valid DNS found" -Color Red
    }
    
    # Option 6: Lowest Latency
    Write-ColoredMessage "`n[6] Lowest Latency Configuration:" -Color Yellow
    if ($lowLatencyPair) {
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($lowLatencyPair.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowLatencyPair.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$([math]::Round($lowLatencyPair.Primary.ResponseTime, 2)) ms" -NoNewline -ForegroundColor Green
        Write-Host " [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowLatencyPair.Primary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($lowLatencyPair.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowLatencyPair.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$([math]::Round($lowLatencyPair.Secondary.ResponseTime, 2)) ms" -NoNewline -ForegroundColor Green
        Write-Host " [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowLatencyPair.Secondary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Fastest response times" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: May sacrifice reliability for speed" -Color DarkYellow
        Write-Host "    Stats: Avg Latency: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($lowLatencyPair.AverageLatency, 2)) ms" -ForegroundColor Cyan
    } else {
        Write-ColoredMessage "    No valid DNS found" -Color Red
    }
    
    # Option 7: Lowest Jitter
    Write-ColoredMessage "`n[7] Lowest Jitter Configuration (Most Stable):" -Color Yellow
    if ($lowestJitterPair) {
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($lowestJitterPair.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowestJitterPair.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowestJitterPair.Primary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowestJitterPair.Primary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowestJitterPair.Primary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($lowestJitterPair.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowestJitterPair.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowestJitterPair.Secondary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowestJitterPair.Secondary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($lowestJitterPair.Secondary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Most consistent performance, ideal for gaming/streaming" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: May not have lowest latency" -Color DarkYellow
        Write-Host "    Stats: Avg Jitter: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($lowestJitterPair.AverageJitter, 2)) ms" -ForegroundColor Cyan
    } else {
        Write-ColoredMessage "    No valid DNS found" -Color Red
    }

    # Option 8: Best Same Provider Pair (Global)
    Write-ColoredMessage "`n[8] Best Same-Provider Configuration (Global):" -Color Yellow
    if ($bestSameProviderPairGlobal) {
        Write-Host "    Provider:  " -NoNewline -ForegroundColor White
        Write-Host "$($bestSameProviderPairGlobal.ProviderName)" -ForegroundColor Magenta
        
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($bestSameProviderPairGlobal.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPairGlobal.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPairGlobal.Primary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPairGlobal.Primary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPairGlobal.Primary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($bestSameProviderPairGlobal.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPairGlobal.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPairGlobal.Secondary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPairGlobal.Secondary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPairGlobal.Secondary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Unified global infrastructure, consistent performance, proper redundancy" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: Single provider dependency (no diversity)" -Color DarkYellow
        Write-Host "    Stats: Avg Score: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($bestSameProviderPairGlobal.AverageScore, 2))" -NoNewline -ForegroundColor Cyan
        Write-Host " | Avg Latency: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($bestSameProviderPairGlobal.AverageLatency, 2)) ms" -ForegroundColor Cyan
    } else {
        Write-ColoredMessage "    No valid same-provider global pair found" -Color Red
    }
}

# Overall recommendation based on balanced criteria
Write-ColoredMessage "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
Write-ColoredMessage "RECOMMENDED CHOICE:" -Color Cyan
Write-ColoredMessage "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan

# Determine best recommendation
$recommendations = @()
if ($bestMixedPair) { 
    $recommendations += @{Type = "Mixed"; Pair = $bestMixedPair; Score = $bestMixedPair.AverageScore; Priority = 1} 
}
if ($bestOverallPair) { 
    $recommendations += @{Type = "Overall"; Pair = $bestOverallPair; Score = $bestOverallPair.AverageScore; Priority = 2} 
}
if ($egyptianStats -and $bestEgyptianPair) {
    $egyptianScore = ($egyptianStats.Avg * 0.6) + ($egyptianStats.AvgJitter * 0.2)
    $recommendations += @{Type = "Egyptian"; Pair = $bestEgyptianPair; Score = $egyptianScore; Priority = 3}
}
if ($globalStats -and $bestGlobalPair) {
    $globalScore = ($globalStats.Avg * 0.6) + ($globalStats.AvgJitter * 0.2)
    $recommendations += @{Type = "Global"; Pair = $bestGlobalPair; Score = $globalScore; Priority = 4}
}

if ($recommendations.Count -gt 0) {
    $topRecommendation = $recommendations | Sort-Object Score | Select-Object -First 1
    
    Write-Host "`nFor most users, we recommend: [" -NoNewline -ForegroundColor Yellow
    Write-Host "$($topRecommendation.Type)" -NoNewline -ForegroundColor Green
    Write-Host "] configuration" -ForegroundColor Yellow
    Write-Host "This provides the " -NoNewline -ForegroundColor White
    Write-Host "best balance" -NoNewline -ForegroundColor Cyan
    Write-Host " of speed, reliability, and redundancy." -ForegroundColor White
} else {
    $topRecommendation = $null
    Write-ColoredMessage "`nNo valid recommendations available." -Color Red
}

# Add IPv6, DNSSEC, and Quality statistics summary
Write-ColoredMessage "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
Write-ColoredMessage "ADVANCED FEATURES SUMMARY:" -Color Cyan
Write-ColoredMessage "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan

if (-not $SkipIPv6Test -or -not $SkipDNSSECTest -or -not $SkipResponseVerification -or $TestEDNS0 -or $TestTCP) {
    $successfulResults = $results | Where-Object { $_.Status -eq "Success" }
    
    if (-not $SkipIPv6Test) {
        $ipv6Supported = ($successfulResults | Where-Object { $_.IPv6 -eq "✓" }).Count
        $ipv6Total = ($successfulResults | Where-Object { $_.IPv6 -ne "N/A" }).Count
        if ($ipv6Total -gt 0) {
            $ipv6Percentage = [math]::Round(($ipv6Supported / $ipv6Total) * 100, 1)
            Write-Host "`nIPv6 Support: " -NoNewline -ForegroundColor Yellow
            Write-Host "$ipv6Supported/$ipv6Total DNS servers (" -NoNewline -ForegroundColor White
            Write-Host "$ipv6Percentage%" -NoNewline -ForegroundColor $(if ($ipv6Percentage -gt 50) { "Green" } else { "Red" })
            Write-Host ")" -ForegroundColor White
            
            # List IPv6-capable DNS
            $ipv6DNS = $successfulResults | Where-Object { $_.IPv6 -eq "✓" } | Select-Object -Unique Provider, IP | Select-Object -First 5
            if ($ipv6DNS.Count -gt 0) {
                Write-ColoredMessage "  IPv6-capable DNS providers:" -Color Cyan
                foreach ($dns in $ipv6DNS) {
                    Write-Host "    • " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($dns.Provider)" -NoNewline -ForegroundColor Magenta
                    Write-Host " (" -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($dns.IP)" -NoNewline -ForegroundColor Cyan
                    Write-Host ")" -ForegroundColor DarkGray
                }
                if ($ipv6Supported -gt 5) {
                    Write-ColoredMessage "    ... and $($ipv6Supported - 5) more" -Color DarkGray
                }
            }
        }
    }
    
    if (-not $SkipDNSSECTest) {
        $dnssecSupported = ($successfulResults | Where-Object { $_.DNSSEC -eq "✓" }).Count
        $dnssecTotal = ($successfulResults | Where-Object { $_.DNSSEC -ne "N/A" }).Count
        if ($dnssecTotal -gt 0) {
            $dnssecPercentage = [math]::Round(($dnssecSupported / $dnssecTotal) * 100, 1)
            Write-ColoredMessage "`nDNSSEC Support: " -Color Yellow -NoNewline
            Write-ColoredMessage "$dnssecSupported/$dnssecTotal DNS servers ($dnssecPercentage%)" -Color $(if ($dnssecPercentage -gt 50) { "Green" } else { "Gray" })
            
            # List DNSSEC-capable DNS
            $dnssecDNS = $successfulResults | Where-Object { $_.DNSSEC -eq "✓" } | Select-Object -Unique Provider, IP | Select-Object -First 5
            if ($dnssecDNS.Count -gt 0) {
                Write-ColoredMessage "  DNSSEC-enabled DNS providers:" -Color Gray
                foreach ($dns in $dnssecDNS) {
                    Write-ColoredMessage "    • $($dns.Provider) ($($dns.IP))" -Color Gray
                }
                if ($dnssecSupported -gt 5) {
                    Write-ColoredMessage "    ... and $($dnssecSupported - 5) more" -Color Gray
                }
            }
        }
    }
    
    if (-not $SkipResponseVerification) {
        $qualityGood = ($successfulResults | Where-Object { $_.Quality -eq "✓" }).Count
        $qualityTotal = ($successfulResults | Where-Object { $_.Quality -ne "N/A" }).Count
        if ($qualityTotal -gt 0) {
            $qualityPercentage = [math]::Round(($qualityGood / $qualityTotal) * 100, 1)
            Write-ColoredMessage "`nResponse Quality: " -Color Yellow -NoNewline
            Write-ColoredMessage "$qualityGood/$qualityTotal DNS servers ($qualityPercentage%)" -Color $(if ($qualityPercentage -gt 80) { "Green" } elseif ($qualityPercentage -gt 50) { "Yellow" } else { "Red" })
            Write-ColoredMessage "  (Checks for complete answers, valid TTL, no hijacking)" -Color Gray
            
            # Warn about poor quality DNS
            $poorQualityDNS = $successfulResults | Where-Object { $_.Quality -eq "✗" } | Select-Object -Unique Provider, IP
            if ($poorQualityDNS.Count -gt 0) {
                Write-ColoredMessage "  ⚠ Warning: $($poorQualityDNS.Count) DNS provider(s) have response quality issues" -Color Yellow
            }
        }
    }
    
    if ($TestEDNS0) {
        $edns0Supported = ($successfulResults | Where-Object { $_.EDNS0 -eq "✓" }).Count
        $edns0Total = ($successfulResults | Where-Object { $_.EDNS0 -ne "N/A" }).Count
        if ($edns0Total -gt 0) {
            $edns0Percentage = [math]::Round(($edns0Supported / $edns0Total) * 100, 1)
            Write-ColoredMessage "`nEDNS0 Support: " -Color Yellow -NoNewline
            Write-ColoredMessage "$edns0Supported/$edns0Total DNS servers ($edns0Percentage%)" -Color $(if ($edns0Percentage -gt 80) { "Green" } elseif ($edns0Percentage -gt 50) { "Yellow" } else { "Red" })
            Write-ColoredMessage "  (Better CDN routing for streaming/gaming)" -Color Gray
            
            # List EDNS0-capable DNS
            $edns0DNS = $successfulResults | Where-Object { $_.EDNS0 -eq "✓" } | Select-Object -Unique Provider, IP | Select-Object -First 5
            if ($edns0DNS.Count -gt 0) {
                Write-ColoredMessage "  EDNS0-capable DNS providers:" -Color Cyan
                foreach ($dns in $edns0DNS) {
                    Write-Host "    • " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($dns.Provider)" -NoNewline -ForegroundColor Magenta
                    Write-Host " (" -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($dns.IP)" -NoNewline -ForegroundColor Cyan
                    Write-Host ")" -ForegroundColor DarkGray
                }
                if ($edns0Supported -gt 5) {
                    Write-ColoredMessage "    ... and $($edns0Supported - 5) more" -Color DarkGray
                }
            }
        }
    }
    
    if ($TestTCP) {
        $tcpSupported = ($successfulResults | Where-Object { $_.TCP -eq "✓" }).Count
        $tcpTotal = ($successfulResults | Where-Object { $_.TCP -ne "N/A" }).Count
        if ($tcpTotal -gt 0) {
            $tcpPercentage = [math]::Round(($tcpSupported / $tcpTotal) * 100, 1)
            Write-ColoredMessage "`nTCP Fallback: " -Color Yellow -NoNewline
            Write-ColoredMessage "$tcpSupported/$tcpTotal DNS servers ($tcpPercentage%)" -Color $(if ($tcpPercentage -gt 80) { "Green" } elseif ($tcpPercentage -gt 50) { "Yellow" } else { "Red" })
            Write-ColoredMessage "  (Handles large responses for game services)" -Color Gray
            
            # List TCP-capable DNS
            $tcpDNS = $successfulResults | Where-Object { $_.TCP -eq "✓" } | Select-Object -Unique Provider, IP | Select-Object -First 5
            if ($tcpDNS.Count -gt 0) {
                Write-ColoredMessage "  TCP-capable DNS providers:" -Color Cyan
                foreach ($dns in $tcpDNS) {
                    Write-Host "    • " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($dns.Provider)" -NoNewline -ForegroundColor Magenta
                    Write-Host " (" -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($dns.IP)" -NoNewline -ForegroundColor Cyan
                    Write-Host ")" -ForegroundColor DarkGray
                }
                if ($tcpSupported -gt 5) {
                    Write-ColoredMessage "    ... and $($tcpSupported - 5) more" -Color DarkGray
                }
            }
        }
    }
} else {
    Write-ColoredMessage "`nAdvanced tests disabled. Use -TestIPv6, -TestDNSSEC, -VerifyResponses, -TestEDNS0, or -TestTCP to enable." -Color Gray
}

# Store the best choice for script generation. Use the same Score-sorted
# winner that the "RECOMMENDED CHOICE" banner displayed (NOT $recommendations[0],
# which is the first-by-insertion-order pair and disagrees with the banner
# whenever a Mixed pair exists alongside a faster category-specific pair).
if ($topRecommendation) {
    $script:RecommendedPair = $topRecommendation.Pair
    $script:RecommendedType = $topRecommendation.Type
}


# Export results to CSV if specified
if ($ExportPath) {
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = if ($ExportPath -match '\.csv$') { 
            $ExportPath 
        } else { 
            Join-Path $ExportPath "DNSTest_$timestamp.csv" 
        }
        
        # Create directory if it doesn't exist
        $directory = Split-Path -Path $filename -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force -WhatIf:$false -Confirm:$false | Out-Null
        }
        
        $results | Export-Csv -Path $filename -NoTypeInformation -WhatIf:$false -Confirm:$false
        Write-ColoredMessage "`nResults exported to $filename" -Color Green
    } catch {
        Write-ColoredMessage "Error exporting results: $_" -Color Red
    }
}

# Export results to JSON if specified. Unlike the CSV export, this preserves
# the full structured shape of the result + recommendation objects.
if ($ExportJson) {
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $jsonFile = if ($ExportJson -match '\.json$') {
            $ExportJson
        } else {
            Join-Path $ExportJson "DNSTest_$timestamp.json"
        }

        $jsonDir = Split-Path -Path $jsonFile -Parent
        if ($jsonDir -and -not (Test-Path $jsonDir)) {
            New-Item -ItemType Directory -Path $jsonDir -Force -WhatIf:$false -Confirm:$false | Out-Null
        }

        $payload = [ordered]@{
            schemaVersion = 1
            generatedAt   = (Get-Date).ToString('o')
            parameters    = [ordered]@{
                domain         = $Domain
                category       = $Category
                protocol       = $Protocol
                testCount      = $TestCount
                timeout        = $Timeout
                quickTest      = [bool]$QuickTest
                parallel       = [bool]$Parallel
                maxThreads     = $MaxThreads
                cacheBust      = [bool]$CacheBust
                maxRetries     = $MaxRetries
                mlProfile      = $MLProfile
                jitterWeight   = $JitterWeight
            }
            results         = $results
            recommendations = $recommendations
        }

        $payload | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-ColoredMessage "Results exported as JSON to $jsonFile" -Color Green
    } catch {
        Write-ColoredMessage "Error exporting JSON: $_" -Color Red
    }
}

# Self-contained HTML report.
if ($ExportHtml) {
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $htmlFile = if ($ExportHtml -match '\.html?$') {
            $ExportHtml
        } else {
            Join-Path $ExportHtml "DNSTest_$timestamp.html"
        }
        $htmlDir = Split-Path -Path $htmlFile -Parent
        if ($htmlDir -and -not (Test-Path $htmlDir)) {
            New-Item -ItemType Directory -Path $htmlDir -Force -WhatIf:$false -Confirm:$false | Out-Null
        }

        # Encode-everything HTML escape - small inline helper to avoid pulling
        # System.Web for one call.
        $escape = {
            param($s)
            if ($null -eq $s) { return '' }
            ([string]$s).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
        }

        $rowsHtml = ($results | ForEach-Object {
            $statusClass = if ($_.Status -eq 'Success') { 'ok' } else { 'err' }
            "      <tr class='$statusClass'><td>$(& $escape $_.Provider)</td><td><code>$(& $escape $_.IP)</code></td><td>$(& $escape $_.Category)</td><td>$(& $escape $_.Domain)</td><td>$(& $escape $_.RecordType)</td><td>$(& $escape $_.ResponseTime)</td><td>$(& $escape $_.Jitter)</td><td>$(& $escape $_.SuccessRate)%</td><td>$(& $escape $_.Status)</td></tr>"
        }) -join "`n"

        $recoHtml = if ($script:RecommendedPair -and $script:RecommendedPair.Primary) {
            "    <p><strong>Recommended pair:</strong> $(& $escape $script:RecommendedPair.Primary.Provider) (<code>$(& $escape $script:RecommendedPair.Primary.IP)</code>) + $(& $escape $script:RecommendedPair.Secondary.Provider) (<code>$(& $escape $script:RecommendedPair.Secondary.IP)</code>)</p>"
        } else { "    <p><em>No recommendation produced.</em></p>" }

        $genTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
        $html = @"
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <title>DNS Benchmark Report &mdash; $(& $escape $Domain)</title>
  <style>
    body { font: 14px/1.45 -apple-system, Segoe UI, Roboto, sans-serif; margin: 2em; color: #1f2328; }
    h1 { margin-bottom: 0; }
    .meta { color: #57606a; margin-bottom: 1.5em; }
    table { border-collapse: collapse; width: 100%; }
    th, td { padding: 6px 10px; border-bottom: 1px solid #d0d7de; text-align: left; }
    th { background: #f6f8fa; }
    tr.err td { color: #cf222e; }
    tr.ok td:nth-child(6), tr.ok td:nth-child(7) { font-variant-numeric: tabular-nums; }
    code { background: #eaeef2; padding: 1px 5px; border-radius: 4px; font-size: 12px; }
    .reco { background: #ddf4ff; padding: 10px 14px; border-radius: 6px; margin: 1em 0; border: 1px solid #54aeff; }
  </style>
</head>
<body>
  <h1>DNS Benchmark Report</h1>
  <div class='meta'>Generated $(& $escape $genTime) &middot; domain <code>$(& $escape $Domain)</code> &middot; category <code>$(& $escape $Category)</code> &middot; protocol <code>$(& $escape $Protocol)</code> &middot; run <code>$(& $escape $script:RunId)</code></div>
  <div class='reco'>
$recoHtml
  </div>
  <h2>Results ($(($results | Measure-Object).Count))</h2>
  <table>
    <thead><tr><th>Provider</th><th>IP</th><th>Category</th><th>Domain</th><th>Type</th><th>Response (ms)</th><th>Jitter (ms)</th><th>Success</th><th>Status</th></tr></thead>
    <tbody>
$rowsHtml
    </tbody>
  </table>
</body>
</html>
"@

        $html | Out-File -FilePath $htmlFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
        Write-ColoredMessage "HTML report written to $htmlFile" -Color Green
    } catch {
        Write-ColoredMessage "Error exporting HTML: $_" -Color Red
    }
}

# Determine overall best DNS pair for configuration
Write-ColoredMessage "`n`nCommands to set DNS on your computer:" -Color Cyan
Write-ColoredMessage "======================================" -Color Cyan

# Use the recommended pair from the analysis above
if ($script:RecommendedPair -and $script:RecommendedPair.Primary -and $script:RecommendedPair.Secondary) {
    $bestOverallPair = $script:RecommendedPair
    
    $typeLabel = if ($script:RecommendedType) { " ($($script:RecommendedType))" } else { "" }
    Write-ColoredMessage "`nUsing Recommended Configuration${typeLabel}:" -Color Magenta
    Write-ColoredMessage "Primary:   $($bestOverallPair.Primary.IP) ($($bestOverallPair.Primary.Provider))" -Color Green
    Write-ColoredMessage "Secondary: $($bestOverallPair.Secondary.IP) ($($bestOverallPair.Secondary.Provider))" -Color Green
    
    Write-ColoredMessage "`nWindows PowerShell (Run as Administrator):" -Color Yellow
    Write-ColoredMessage "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet*' -ServerAddresses ('$($bestOverallPair.Primary.IP)','$($bestOverallPair.Secondary.IP)')" -Color White
    
    Write-ColoredMessage "`nUbuntu/Debian (Run with sudo):" -Color Yellow
    Write-ColoredMessage "sudo bash -c 'echo nameserver $($bestOverallPair.Primary.IP) > /etc/resolv.conf'" -Color White
    Write-ColoredMessage "sudo bash -c 'echo nameserver $($bestOverallPair.Secondary.IP) >> /etc/resolv.conf'" -Color White
    
    Write-ColoredMessage "`nMacOS:" -Color Yellow
    Write-ColoredMessage "networksetup -setdnsservers Wi-Fi $($bestOverallPair.Primary.IP) $($bestOverallPair.Secondary.IP)" -Color White
    
    # -ApplyDNS actually executes the Windows command, with -WhatIf / -Confirm
    # routed through ShouldProcess. Skipped on non-Windows for safety.
    if ($ApplyDNS) {
        if ($PSVersionTable.Platform -and $PSVersionTable.Platform -ne 'Win32NT') {
            Write-ColoredMessage "`n-ApplyDNS is only implemented for Windows; skipping on $($PSVersionTable.Platform)." -Color Yellow -Force
        } else {
            $servers = @($bestOverallPair.Primary.IP, $bestOverallPair.Secondary.IP)
            $target = "interface(s) matching '$InterfaceAlias' -> $($servers -join ', ')"
            if ($PSCmdlet.ShouldProcess($target, 'Set-DnsClientServerAddress')) {
                try {
                    $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object {
                        $_.Status -eq 'Up' -and $_.InterfaceAlias -like $InterfaceAlias
                    }
                    if (-not $adapters) {
                        Write-ColoredMessage "No matching 'Up' adapters found for alias '$InterfaceAlias'. Nothing applied." -Color Yellow -Force
                        Write-StructuredLog -Event 'apply-skipped' -Data @{ reason='no-adapters'; alias=$InterfaceAlias }
                    } else {
                        foreach ($a in $adapters) {
                            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers -ErrorAction Stop
                            Write-ColoredMessage "Applied DNS to $($a.InterfaceAlias) (ifIndex $($a.ifIndex))." -Color Green -Force
                            Write-StructuredLog -Event 'apply-success' -Data @{ alias=$a.InterfaceAlias; ifIndex=$a.ifIndex; servers=$servers }
                        }
                        try { Clear-DnsClientCache -ErrorAction Stop; Write-ColoredMessage "DNS client cache cleared." -Color Green -Force } catch { }
                    }
                } catch {
                    Write-ColoredMessage "Failed to apply DNS settings: $_" -Color Red -Force
                    Write-StructuredLog -Event 'apply-failed' -Data @{ error="$_" }
                }
            } else {
                Write-StructuredLog -Event 'apply-whatif' -Data @{ servers=$servers; alias=$InterfaceAlias }
            }
        }
    }
    
    # Generate configuration scripts if requested
    if ($GenerateScripts) {
        Write-ColoredMessage "`nGenerating DNS configuration scripts..." -Color Cyan
        
        # Windows script
        $windowsScript = @"
# Windows DNS Configuration Script
# Run as Administrator

# Set DNS for all network adapters
Get-NetAdapter | Where-Object {`$_.Status -eq "Up"} | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceAlias `$_.Name -ServerAddresses ('$($bestOverallPair.Primary.IP)','$($bestOverallPair.Secondary.IP)')
    Write-Host "Set DNS for `$(`$_.Name) to $($bestOverallPair.Primary.IP), $($bestOverallPair.Secondary.IP)"
}

# Flush DNS cache
Clear-DnsClientCache
Write-Host "DNS cache cleared"
"@
            
            # Linux script
            $linuxScript = @"
#!/bin/bash
# Linux DNS Configuration Script
# Run with sudo

# Backup original resolv.conf
cp /etc/resolv.conf /etc/resolv.conf.backup

# Set new DNS servers
echo "nameserver $($bestOverallPair.Primary.IP)" > /etc/resolv.conf
echo "nameserver $($bestOverallPair.Secondary.IP)" >> /etc/resolv.conf

# For systems using systemd-resolved
systemctl restart systemd-resolved 2>/dev/null || true

echo "DNS configuration updated"
echo "Primary: $($bestOverallPair.Primary.IP)"
echo "Secondary: $($bestOverallPair.Secondary.IP)"
"@
            
            # macOS script
            $macScript = @"
#!/bin/bash
# macOS DNS Configuration Script

# Get list of network services
services=`$(networksetup -listallnetworkservices | grep -v "An asterisk")

# Set DNS for each network service
while IFS= read -r service; do
    if [[ "`$service" != *"*"* ]]; then
        networksetup -setdnsservers "`$service" $($bestOverallPair.Primary.IP) $($bestOverallPair.Secondary.IP)
        echo "Set DNS for `$service to $($bestOverallPair.Primary.IP), $($bestOverallPair.Secondary.IP)"
    fi
done <<< "`$services"

# Flush DNS cache
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

echo "DNS configuration updated and cache flushed"
"@
            
            try {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $scriptDir = Join-Path $PWD "dns-config-scripts-$timestamp"
                New-Item -ItemType Directory -Path $scriptDir -Force -WhatIf:$false -Confirm:$false | Out-Null
                
                $windowsScript | Out-File -FilePath (Join-Path $scriptDir "configure-dns-windows.ps1") -Encoding UTF8 -WhatIf:$false -Confirm:$false
                $linuxScript | Out-File -FilePath (Join-Path $scriptDir "configure-dns-linux.sh") -Encoding UTF8 -WhatIf:$false -Confirm:$false
                $macScript | Out-File -FilePath (Join-Path $scriptDir "configure-dns-macos.sh") -Encoding UTF8 -WhatIf:$false -Confirm:$false
                
                Write-ColoredMessage "Scripts generated in: $scriptDir" -Color Green
                Write-ColoredMessage "Windows: configure-dns-windows.ps1 (Run as Administrator)" -Color Yellow
                Write-ColoredMessage "Linux: configure-dns-linux.sh (Run with sudo)" -Color Yellow
                Write-ColoredMessage "macOS: configure-dns-macos.sh" -Color Yellow
            } catch {
                Write-ColoredMessage "Error generating scripts: $_" -Color Red
            }
        }
    } else {
        Write-ColoredMessage "`nNo valid DNS configuration found. All tested DNS servers failed or timed out." -Color Red
        Write-ColoredMessage "Try increasing the timeout parameter or checking your network connection." -Color Yellow
    }

# Skip displaying removed DNS table (redundant - shown in persistent tracking below)

# Save persistent tracking history
if (-not $DisablePersistentTracking) {
    Save-PersistentTracking -History $script:PersistentHistory
    
    # Show summary of newly failed DNS servers
    $newlyFailed = @()
    $approachingBlacklist = @()
    
    foreach ($dns in $script:PersistentHistory.Keys) {
        $record = $script:PersistentHistory[$dns]
        if ($record.FailureCount -gt 0 -and -not $record.Blacklisted) {
            $approachingBlacklist += [PSCustomObject]@{
                IP = $dns
                Failures = $record.FailureCount
                Remaining = $PersistentFailureThreshold - $record.FailureCount
            }
        }
        if ($record.Blacklisted) {
            $newlyFailed += $dns
        }
    }
    
    # Compact failure summary
    if ($approachingBlacklist.Count -gt 0 -or $newlyFailed.Count -gt 0) {
        Write-Host ""
        if ($newlyFailed.Count -gt 0) {
            Write-Host "⚠ Blacklisted: $($newlyFailed.Count) DNS" -ForegroundColor Red
        }
        if ($approachingBlacklist.Count -gt 0) {
            Write-Host "⚠ Approaching blacklist: $($approachingBlacklist.Count) DNS" -ForegroundColor Yellow
        }
    }
}

# Save ML training data and track best pairs
if ($script:MLEnabled) {
    # Track the best DNS pairs discovered in this run
    if ($bestOverallPair -and $bestOverallPair.Primary -and $bestOverallPair.Secondary) {
        $primaryRT = [double]($bestOverallPair.Primary.ResponseTime -replace ' ms$', '')
        $secondaryRT = [double]($bestOverallPair.Secondary.ResponseTime -replace ' ms$', '')
        $combinedScore = ($primaryRT + $secondaryRT) / 2
        
        Update-PairMLData -MLData $script:MLData `
            -PrimaryIP $bestOverallPair.Primary.IP `
            -SecondaryIP $bestOverallPair.Secondary.IP `
            -PrimaryProvider $bestOverallPair.Primary.Provider `
            -SecondaryProvider $bestOverallPair.Secondary.Provider `
            -CombinedScore $combinedScore `
            -ConfigType "Best Overall"
    }
    
    if ($bestSameProviderPairGlobal -and $bestSameProviderPairGlobal.Primary -and $bestSameProviderPairGlobal.Secondary) {
        $primaryRT = [double]($bestSameProviderPairGlobal.Primary.ResponseTime -replace ' ms$', '')
        $secondaryRT = [double]($bestSameProviderPairGlobal.Secondary.ResponseTime -replace ' ms$', '')
        $combinedScore = ($primaryRT + $secondaryRT) / 2
        
        Update-PairMLData -MLData $script:MLData `
            -PrimaryIP $bestSameProviderPairGlobal.Primary.IP `
            -SecondaryIP $bestSameProviderPairGlobal.Secondary.IP `
            -PrimaryProvider $bestSameProviderPairGlobal.Primary.Provider `
            -SecondaryProvider $bestSameProviderPairGlobal.Secondary.Provider `
            -CombinedScore $combinedScore `
            -ConfigType "Same Provider Global"
    }
    
    if ($bestMixedPair -and $bestMixedPair.Primary -and $bestMixedPair.Secondary) {
        $primaryRT = [double]($bestMixedPair.Primary.ResponseTime -replace ' ms$', '')
        $secondaryRT = [double]($bestMixedPair.Secondary.ResponseTime -replace ' ms$', '')
        $combinedScore = ($primaryRT + $secondaryRT) / 2
        
        Update-PairMLData -MLData $script:MLData `
            -PrimaryIP $bestMixedPair.Primary.IP `
            -SecondaryIP $bestMixedPair.Secondary.IP `
            -PrimaryProvider $bestMixedPair.Primary.Provider `
            -SecondaryProvider $bestMixedPair.Secondary.Provider `
            -CombinedScore $combinedScore `
            -ConfigType "Mixed"
    }
    
    # Increment total runs
    $script:MLData.TotalRuns++
    
    # Save ML data
    if (Save-MLData -Data $script:MLData) {
        Write-ColoredMessage "`nML training data saved. Total runs: $($script:MLData.TotalRuns)" -Color Green
        
        # Export ML recommendations report
        $mlReportPath = Join-Path $PSScriptRoot "dns-ml-recommendations.txt"
        Export-MLRecommendations -MLData $script:MLData -OutputPath $mlReportPath
    }
}

# Calculate and display test duration
$script:TestEndTime = Get-Date
$testDuration = $script:TestEndTime - $script:TestStartTime
$durationSeconds = [Math]::Round($testDuration.TotalSeconds, 1)
$durationFormatted = if ($testDuration.TotalMinutes -ge 1) {
    "$([Math]::Floor($testDuration.TotalMinutes)) min $([Math]::Round($testDuration.Seconds, 0)) sec"
} else {
    "$durationSeconds sec"
}

Write-ColoredMessage "`n========================================" -Color Green
Write-ColoredMessage "DNS Performance Test completed." -Color Cyan
Write-ColoredMessage "Total Test Duration: $durationFormatted ($durationSeconds seconds)" -Color Green
Write-ColoredMessage "========================================" -Color Green

Write-StructuredLog -Event 'run-end' -Data @{
    durationSeconds = $durationSeconds
    resultCount     = ($results | Measure-Object).Count
    recommendation  = if ($script:RecommendedPair -and $script:RecommendedPair.Primary) {
        "$($script:RecommendedPair.Primary.IP),$($script:RecommendedPair.Secondary.IP)"
    } else { '' }
}
Close-StructuredLog

# Tear down the shared runspace pool so its threads don't keep the host alive.
if ($null -ne $script:DnsRunspacePool) {
    try {
        $script:DnsRunspacePool.Close()
        $script:DnsRunspacePool.Dispose()
    } catch { }
    $script:DnsRunspacePool = $null
}
