# DNS Performance Test Script
# Tests DNS providers for speed and reliability
# Created: May 2025

[CmdletBinding()]
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
      [Parameter(HelpMessage="Test only specific DNS categories: All, Egyptian, Global, ControlD (default: All)")]
    [ValidateSet("All", "Egyptian", "Global", "ControlD")]
    [string]$Category = "All",
    
    [Parameter(HelpMessage="Path to export results as CSV")]
    [string]$ExportPath,
    
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
    [switch]$SkipResponseVerification
)

# Check if required modules are available
if (-not (Get-Command "Resolve-DnsName" -ErrorAction SilentlyContinue)) {
    Write-Host "The required cmdlet 'Resolve-DnsName' is not available on your system." -ForegroundColor Red
    Write-Host "This script requires Windows PowerShell 5.1 or later with the DnsClient module." -ForegroundColor Red
    exit 1
}

# Apply quick test mode settings
# Apply quick test mode settings
if ($QuickTest) {
    $TestCount = [math]::Max(1, [math]::Floor($TestCount / 2))
    $AggressiveMode = $true
    $DisableFailureRemoval = $false
    
    # QuickTest optimizations:
    # 1. Reduce timeout for faster failure detection (but not too short)
    if ($Timeout -gt 2) {
        $Timeout = 2
    }
    
    # 2. Skip parallel mode overhead in quick tests (sequential is faster for quick tests)
    $Parallel = $false
    
    # 3. Focus on previously successful DNS servers first (if history exists)
    $script:QuickTestMode = $true
}

# Global variables for failure tracking
$global:DnsFailureTracker = @{}
$global:DnsSuccessTracker = @{}
$global:RemovedDnsProviders = @()
$global:PersistentTrackingFile = Join-Path $PSScriptRoot "dns-failure-history.json"

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
    
    if (Test-Path $global:PersistentTrackingFile) {
        try {
            $content = Get-Content $global:PersistentTrackingFile -Raw | ConvertFrom-Json
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
            Write-Warning "Failed to load persistent tracking data: $_"
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
        
        $jsonObject | ConvertTo-Json -Depth 10 | Set-Content $global:PersistentTrackingFile -Force
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
    
    if (-not $global:DnsFailureTracker.ContainsKey($key)) {
        $global:DnsFailureTracker[$key] = 0
        $global:DnsSuccessTracker[$key] = 0
    }
    
    if ($Success) {
        $global:DnsSuccessTracker[$key]++
    } else {
        $global:DnsFailureTracker[$key]++
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
    
    if (-not $global:DnsFailureTracker.ContainsKey($key)) {
        return $false
    }
    
    $failures = $global:DnsFailureTracker[$key]
    $successes = $global:DnsSuccessTracker[$key]
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
            if ($global:DnsFailureTracker.ContainsKey($key) -and $global:DnsFailureTracker[$key] -gt 0 -and $global:DnsSuccessTracker[$key] -eq 0) {
                $failures = $global:DnsFailureTracker[$key]
                $successes = $global:DnsSuccessTracker[$key]
                
                # Update persistent tracking for this failure
                if ($PersistentTracking) {
                    Update-PersistentTracking -History $global:PersistentHistory -DnsIP $dns.IP -Failed $true
                }
                
                $global:RemovedDnsProviders += [PSCustomObject]@{
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
            $failures = $global:DnsFailureTracker[$key]
            $successes = $global:DnsSuccessTracker[$key]
            $totalTests = $failures + $successes
            $failureRate = if ($totalTests -gt 0) { [math]::Round(($failures / $totalTests) * 100, 1) } else { 100 }
            
            # Update persistent tracking for this failure
            if (-not $DisablePersistentTracking) {
                Update-PersistentTracking -History $global:PersistentHistory -DnsIP $dns.IP -Failed $true
            }
            
            $global:RemovedDnsProviders += [PSCustomObject]@{
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

# Define popular DNS providers including Egyptian ones
$dnsProviders = @(    # ========== EGYPTIAN DNS PROVIDERS ==========
    
    # Working Egyptian DNS Servers (tested and verified)
    @{ Name = "TE-Data Primary"; IP = "163.121.128.135"; Category = "Egyptian" },
    @{ Name = "TE-Data Secondary"; IP = "163.121.128.134"; Category = "Egyptian" },
    
    # ========== GLOBAL DNS PROVIDERS ==========
    
    # Global DNS Providers (Updated with more options)
    @{ Name = "Google DNS"; IP = "8.8.8.8"; Category = "Global" },
    @{ Name = "Google DNS Secondary"; IP = "8.8.4.4"; Category = "Global" },
    @{ Name = "Cloudflare DNS"; IP = "1.1.1.1"; Category = "Global" },
    @{ Name = "Cloudflare DNS Secondary"; IP = "1.0.0.1"; Category = "Global" },
    @{ Name = "Cloudflare Family"; IP = "1.1.1.3"; Category = "Global" },
    @{ Name = "Cloudflare Family Secondary"; IP = "1.0.0.3"; Category = "Global" },
    @{ Name = "Cloudflare for Teams"; IP = "1.1.1.2"; Category = "Global" },
    @{ Name = "Cloudflare for Teams Alt"; IP = "1.0.0.2"; Category = "Global" },
    @{ Name = "OpenDNS"; IP = "208.67.222.222"; Category = "Global" },
    @{ Name = "OpenDNS Secondary"; IP = "208.67.220.220"; Category = "Global" },
    @{ Name = "OpenDNS Family Shield"; IP = "208.67.222.123"; Category = "Global" },
    @{ Name = "OpenDNS Family Shield 2"; IP = "208.67.220.123"; Category = "Global" },
    @{ Name = "Quad9"; IP = "9.9.9.9"; Category = "Global" },
    @{ Name = "Quad9 Secondary"; IP = "149.112.112.112"; Category = "Global" },
    @{ Name = "Quad9 Secure"; IP = "9.9.9.11"; Category = "Global" },
    @{ Name = "Quad9 Secure Secondary"; IP = "149.112.112.11"; Category = "Global" },
    @{ Name = "Quad9 Unsecured"; IP = "9.9.9.10"; Category = "Global" },
    @{ Name = "Quad9 Unsecured Alt"; IP = "149.112.112.10"; Category = "Global" },
    @{ Name = "AdGuard DNS"; IP = "94.140.14.14"; Category = "Global" },
    @{ Name = "AdGuard DNS Secondary"; IP = "94.140.15.15"; Category = "Global" },
    @{ Name = "AdGuard Family"; IP = "94.140.14.15"; Category = "Global" },
    @{ Name = "AdGuard Family Secondary"; IP = "94.140.15.16"; Category = "Global" },
    @{ Name = "AdGuard Unfiltered"; IP = "94.140.14.140"; Category = "Global" },
    @{ Name = "AdGuard Unfiltered Alt"; IP = "94.140.14.141"; Category = "Global" },
    @{ Name = "CleanBrowsing"; IP = "185.228.168.9"; Category = "Global" },
    @{ Name = "CleanBrowsing Secondary"; IP = "185.228.169.9"; Category = "Global" },
    @{ Name = "CleanBrowsing Adult Filter"; IP = "185.228.168.10"; Category = "Global" },
    @{ Name = "CleanBrowsing Adult Filter 2"; IP = "185.228.169.11"; Category = "Global" },
    @{ Name = "CleanBrowsing Family"; IP = "185.228.168.168"; Category = "Global" },
    @{ Name = "CleanBrowsing Family Alt"; IP = "185.228.169.168"; Category = "Global" },
    @{ Name = "NextDNS"; IP = "45.90.28.167"; Category = "Global" },
    @{ Name = "NextDNS Secondary"; IP = "45.90.30.167"; Category = "Global" },
    @{ Name = "DNS.Watch"; IP = "84.200.69.80"; Category = "Global" },
    @{ Name = "DNS.Watch Secondary"; IP = "84.200.70.40"; Category = "Global" },
    @{ Name = "Comodo Secure DNS"; IP = "8.26.56.26"; Category = "Global" },
    @{ Name = "Comodo Secure DNS 2"; IP = "8.20.247.20"; Category = "Global" },
    @{ Name = "Level3 DNS"; IP = "4.2.2.1"; Category = "Global" },
    @{ Name = "Level3 DNS Secondary"; IP = "4.2.2.2"; Category = "Global" },
    @{ Name = "Level3 Alt 1"; IP = "4.2.2.3"; Category = "Global" },
    @{ Name = "Level3 Alt 2"; IP = "4.2.2.4"; Category = "Global" },
    @{ Name = "Verisign DNS"; IP = "64.6.64.6"; Category = "Global" },
    @{ Name = "Verisign DNS Secondary"; IP = "64.6.65.6"; Category = "Global" },
    
    # Modern Fast DNS Providers
    @{ Name = "Mullvad DNS"; IP = "194.242.2.2"; Category = "Global" },
    @{ Name = "Mullvad DNS Alt"; IP = "193.19.108.2"; Category = "Global" },
    @{ Name = "CIRA Canadian Shield"; IP = "149.112.121.10"; Category = "Global" },
    @{ Name = "CIRA Canadian Shield Alt"; IP = "149.112.122.10"; Category = "Global" },
    @{ Name = "LibreDNS"; IP = "116.202.176.26"; Category = "Global" },
    @{ Name = "LibreDNS Alt"; IP = "95.216.229.153"; Category = "Global" },
    @{ Name = "DeCloudUs DNS"; IP = "176.103.130.130"; Category = "Global" },
    @{ Name = "DeCloudUs DNS Alt"; IP = "176.103.130.131"; Category = "Global" },
    @{ Name = "puntCAT DNS"; IP = "109.69.8.51"; Category = "Global" },
    @{ Name = "puntCAT DNS Alt"; IP = "109.69.8.52"; Category = "Global" },
    @{ Name = "Digitale Gesellschaft"; IP = "185.95.218.42"; Category = "Global" },
    @{ Name = "Digitale Gesellschaft Alt"; IP = "185.95.218.43"; Category = "Global" },
    @{ Name = "Foundation for Applied Privacy"; IP = "146.255.56.98"; Category = "Global" },
    @{ Name = "CZ.NIC ODVR"; IP = "193.17.47.1"; Category = "Global" },
    @{ Name = "CZ.NIC ODVR Alt"; IP = "185.43.135.1"; Category = "Global" },
    @{ Name = "BlahDNS Germany"; IP = "159.69.198.101"; Category = "Global" },
    @{ Name = "BlahDNS Japan"; IP = "45.91.92.121"; Category = "Global" },
    @{ Name = "BlahDNS Singapore"; IP = "194.145.240.6"; Category = "Global" },
    @{ Name = "Snopyta DNS"; IP = "95.216.24.230"; Category = "Global" },
    @{ Name = "Snopyta DNS Alt"; IP = "161.97.219.84"; Category = "Global" },
    @{ Name = "AhaDNS Netherlands"; IP = "5.2.75.75"; Category = "Global" },
    @{ Name = "AhaDNS Los Angeles"; IP = "45.67.219.208"; Category = "Global" },
    @{ Name = "AhaDNS India"; IP = "45.79.120.233"; Category = "Global" },
    @{ Name = "Namecheap DNS"; IP = "198.54.117.10"; Category = "Global" },
    @{ Name = "Namecheap DNS Alt"; IP = "198.54.117.11"; Category = "Global" },
    @{ Name = "Hurricane Electric"; IP = "74.82.42.42"; Category = "Global" },
    @{ Name = "Alternate DNS"; IP = "76.76.19.19"; Category = "Global" },
    @{ Name = "Alternate DNS 2"; IP = "76.223.100.101"; Category = "Global" },
    @{ Name = "UncensoredDNS"; IP = "91.239.100.100"; Category = "Global" },
    @{ Name = "UncensoredDNS Alt"; IP = "89.233.43.71"; Category = "Global" },
    @{ Name = "Safe DNS"; IP = "195.46.39.39"; Category = "Global" },
    @{ Name = "Safe DNS Alt"; IP = "195.46.39.40"; Category = "Global" },
    @{ Name = "FreeDNS"; IP = "37.235.1.174"; Category = "Global" },
    @{ Name = "FreeDNS Alt"; IP = "37.235.1.177"; Category = "Global" },
    @{ Name = "Yandex DNS Basic"; IP = "77.88.8.8"; Category = "Global" },
    @{ Name = "Yandex DNS Basic Alt"; IP = "77.88.8.1"; Category = "Global" },
    @{ Name = "Yandex DNS Safe"; IP = "77.88.8.88"; Category = "Global" },
    @{ Name = "Yandex DNS Family"; IP = "77.88.8.7"; Category = "Global" },
    # Control D DNS Providers (moved to their own category)
    @{ Name = "Control D Standard"; IP = "76.76.2.0"; Category = "ControlD" },
    @{ Name = "Control D Standard Secondary"; IP = "76.76.10.0"; Category = "ControlD" },
    @{ Name = "Control D Uncensored"; IP = "76.76.2.1"; Category = "ControlD" },
    @{ Name = "Control D Uncensored Secondary"; IP = "76.76.10.1"; Category = "ControlD" },
    @{ Name = "Control D Family"; IP = "76.76.2.3"; Category = "ControlD" },
    @{ Name = "Control D Family Secondary"; IP = "76.76.10.3"; Category = "ControlD" }
)

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
        [switch]$NoNewline
    )
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
        $resolveJob = Start-Job -ScriptBlock { 
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
        } -ArgumentList $dnsIP, $domain
        
        if (Wait-Job $resolveJob -Timeout $timeout) {
            $result = Receive-Job $resolveJob
            Remove-Job $resolveJob -Force
            return $result
        } else {
            Remove-Job $resolveJob -Force
            return @{Success = $false; Error = "Timeout"}
        }
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
    
    # Test with a known DNSSEC-enabled domain
    $dnssecDomain = "cloudflare.com"  # Known to have DNSSEC
    
    try {
        $resolveJob = Start-Job -ScriptBlock { 
            param($dnsIP, $domain)
            try {
                # Try to resolve and check for DNSSEC-related records
                $result = Resolve-DnsName -Server $dnsIP -Name $domain -Type A -DnssecOk -ErrorAction Stop
                
                # Check if DNSSEC data is present (AD flag or RRSIG records)
                $hasDnssec = $false
                
                # Check for authenticated data flag or RRSIG presence
                if ($result) {
                    # Try to get DNSKEY records as a DNSSEC indicator
                    $dnskeyResult = Resolve-DnsName -Server $dnsIP -Name $domain -Type DNSKEY -ErrorAction SilentlyContinue
                    $hasDnssec = ($null -ne $dnskeyResult)
                }
                
                return @{
                    Success = $true
                    DNSSECSupported = $hasDnssec
                    ValidationAttempted = $true
                }
            } catch {
                # If the query fails, DNS might not support DNSSEC properly
                return @{
                    Success = $true
                    DNSSECSupported = $false
                    ValidationAttempted = $true
                    Error = $_.Exception.Message
                }
            }
        } -ArgumentList $dnsIP, $dnssecDomain
        
        if (Wait-Job $resolveJob -Timeout $timeout) {
            $result = Receive-Job $resolveJob
            Remove-Job $resolveJob -Force
            return $result
        } else {
            Remove-Job $resolveJob -Force
            return @{Success = $false; DNSSECSupported = $false; ValidationAttempted = $false; Error = "Timeout"}
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
        $resolveJob = Start-Job -ScriptBlock { 
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
        } -ArgumentList $dnsIP, $domain, $recordType
        
        if (Wait-Job $resolveJob -Timeout $timeout) {
            $result = Receive-Job $resolveJob
            Remove-Job $resolveJob -Force
            return $result
        } else {
            Remove-Job $resolveJob -Force
            return @{Success = $false; Error = "Timeout"}
        }
    } catch {
        return @{Success = $false; Error = $_.Exception.Message}
    }
}

# Function to test DNS resolution time with jitter calculation
function Test-DNS {
    param(
        [string]$dnsIP,
        [string]$domain,
        [string]$recordType = "A",
        [string]$category = "Global",
        [string]$providerName = "Unknown"
    )

    $responseTimes = @()
    $successCount = 0
    
    # Get adaptive timeout based on category
    $currentTimeout = Get-AdaptiveTimeout -Category $category -ProviderName $providerName -BaseTimeout $Timeout -EgyptianTimeout $EgyptianTimeout -UseAdaptive $AdaptiveTimeout.IsPresent
    
    Write-ColoredMessage "  Testing reliability ($recordType record, timeout: ${currentTimeout}s)... " -Color Gray -NoNewline

    # First do a single test to check reliability
    try {
        $resolveJob = Start-Job -ScriptBlock { 
            param($dnsIP, $domain, $recordType)
            try {
                Resolve-DnsName -Server $dnsIP -Name $domain -Type $recordType -ErrorAction Stop | Out-Null
                return @{Success = $true}
            } catch {
                return @{Success = $false; Error = $_.Exception.Message}
            }
        } -ArgumentList $dnsIP, $domain, $recordType
        
        if (-not (Wait-Job $resolveJob -Timeout $currentTimeout)) {
            Remove-Job $resolveJob -Force
            Write-ColoredMessage "Failed (timeout)" -Color Red
            Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType; Domain = $domain}
        }
        
        $result = Receive-Job $resolveJob
        Remove-Job $resolveJob -Force
        
        if (-not $result.Success) {
            Write-ColoredMessage "Failed ($($result.Error))" -Color Red
            Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType; Domain = $domain}
        }
    } catch {
        Write-ColoredMessage "Failed (error: $_)" -Color Red
        Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
        return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType; Domain = $domain}
    }

    Write-ColoredMessage "Passed" -Color Green
    
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

            $startTime = Get-Date
            $resolveJob = Start-Job -ScriptBlock { 
                param($dnsIP, $domain, $recordType)
                try {
                    Resolve-DnsName -Server $dnsIP -Name $domain -Type $recordType -ErrorAction Stop | Out-Null
                    return @{Success = $true}
                } catch {
                    return @{Success = $false; Error = $_.Exception.Message}
                }
            } -ArgumentList $dnsIP, $domain, $recordType
            
            if (Wait-Job $resolveJob -Timeout $currentTimeout) {
                $result = Receive-Job $resolveJob
                if ($result.Success) {
                    $endTime = Get-Date
                    $responseTime = ($endTime - $startTime).TotalMilliseconds
                    $responseTimes += $responseTime
                    $successCount++
                    Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $true
                } else {
                    Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
                }
            } else {
                Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
            }
            Remove-Job $resolveJob -Force -ErrorAction SilentlyContinue
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
    
    if ($successCount -eq 0) {
        return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType; Domain = $domain}
    }
    
    # Calculate metrics
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
        SuccessRate = ($successCount / $TestCount) * 100
        ActualTimeout = $currentTimeout
        Domain = $domain
        IPv6Support = $null
        DNSSECSupport = $null
        ResponseQuality = $null
    }
}

# Load persistent tracking history
$global:PersistentHistory = Initialize-PersistentTracking

# Handle reset tracking request
if ($ResetTracking) {
    if (Test-Path $global:PersistentTrackingFile) {
        Remove-Item $global:PersistentTrackingFile -Force
        Write-ColoredMessage "Persistent tracking history has been reset." -Color Green
        $global:PersistentHistory = @{}
    } else {
        Write-ColoredMessage "No tracking history to reset." -Color Yellow
    }
    
    if ($ShowTrackingStats) {
        Show-TrackingStatistics -History $global:PersistentHistory
    }
    exit 0
}

# Show tracking stats if requested
if ($ShowTrackingStats) {
    Show-TrackingStatistics -History $global:PersistentHistory
    if (-not $PSBoundParameters.ContainsKey('Domain')) {
        # Exit if only showing stats
        exit 0
    }
}

# Clear screen and show header
Clear-Host
Write-ColoredMessage "DNS Performance Test" -Color Cyan
Write-ColoredMessage "===================" -Color Cyan
if ($QuickTest) {
    Write-ColoredMessage "Quick test mode: Reduced test count, enabled aggressive failure removal" -Color Yellow
}
Write-ColoredMessage "Testing DNS servers response time for: " -Color Yellow -NoNewline
Write-ColoredMessage ($testDomains -join ', ') -Color Green
Write-ColoredMessage "Mode: $(if ($Parallel) { 'Parallel' } else { 'Sequential' })" -Color Yellow
Write-ColoredMessage "Testing $(if ($Category -eq 'All') { 'all' } else { $Category }) DNS providers" -Color Yellow
Write-ColoredMessage "Record types: $($recordTypes -join ', ')" -Color Yellow
Write-ColoredMessage "Tests per DNS: $TestCount with $Timeout second timeout" -Color Yellow

# Show info about additional tests
$additionalTests = @()
if (-not $SkipIPv6Test) { $additionalTests += "IPv6" }
if (-not $SkipDNSSECTest) { $additionalTests += "DNSSEC" }
if (-not $SkipResponseVerification) { $additionalTests += "Quality" }
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
        Write-ColoredMessage "Aggressive mode: DNS servers will be removed immediately after first failure" -Color Yellow
    }
}
Write-ColoredMessage "===================" -Color Cyan

# Check network connectivity before proceeding
if (-not (Test-NetworkConnectivity)) {
    exit 1
}

# Filter DNS providers by category
$filteredDnsProviders = if ($Category -eq "All") {
    $dnsProviders 
} else { 
    $dnsProviders | Where-Object { $_.Category -eq $Category } 
}

if ($filteredDnsProviders.Count -eq 0) {
    Write-ColoredMessage "No DNS providers match the specified category: $Category" -Color Red
    exit 1
}

# Filter out blacklisted DNS providers
if (-not $DisablePersistentTracking) {
    $blacklistedIPs = Get-BlacklistedDNS -History $global:PersistentHistory
    
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

# QuickTest optimization: Sort DNS providers by historical success
if ($QuickTest -and -not $DisablePersistentTracking -and $global:PersistentHistory.Keys.Count -gt 0) {
    Write-ColoredMessage "QuickTest: Prioritizing historically reliable DNS servers..." -Color Cyan
    
    $filteredDnsProviders = $filteredDnsProviders | Sort-Object {
        $ip = $_.IP
        if ($global:PersistentHistory.ContainsKey($ip)) {
            $record = $global:PersistentHistory[$ip]
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
}

# Create results array
$results = @()

# Test each DNS provider
if ($Parallel) {
    Write-ColoredMessage "`nRunning tests in parallel mode (faster but less precise timing)" -Color Yellow
    
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
                        
                        # Reliability test
                        try {
                            $resolveJob = Start-Job -ScriptBlock { 
                                param($dnsIP, $domain, $recordType)
                                try {
                                    Resolve-DnsName -Server $dnsIP -Name $domain -Type $recordType -ErrorAction Stop | Out-Null
                                    return @{Success = $true}
                                } catch {
                                    return @{Success = $false; Error = $_.Exception.Message}
                                }
                            } -ArgumentList $dnsIP, $domain, $recordType
                            
                            if (-not (Wait-Job $resolveJob -Timeout $timeout)) {
                                Remove-Job $resolveJob -Force
                                return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
                            }
                            
                            $result = Receive-Job $resolveJob
                            Remove-Job $resolveJob -Force
                            
                            if (-not $result.Success) {
                                return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
                            }
                        } catch {
                            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
                        }

                        # Performance testing
                        for ($i = 1; $i -le $testCount; $i++) {
                            try {
                                $startTime = Get-Date
                                $resolveJob = Start-Job -ScriptBlock { 
                                    param($dnsIP, $domain, $recordType)
                                    try {
                                        Resolve-DnsName -Server $dnsIP -Name $domain -Type $recordType -ErrorAction Stop | Out-Null
                                        return @{Success = $true}
                                    } catch {
                                        return @{Success = $false; Error = $_.Exception.Message}
                                    }
                                } -ArgumentList $dnsIP, $domain, $recordType
                                
                                if (Wait-Job $resolveJob -Timeout $timeout) {
                                    $result = Receive-Job $resolveJob
                                    if ($result.Success) {
                                        $endTime = Get-Date
                                        $responseTime = ($endTime - $startTime).TotalMilliseconds
                                        $responseTimes += $responseTime
                                        $successCount++
                                    }
                                }
                                Remove-Job $resolveJob -Force -ErrorAction SilentlyContinue
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
                
                # Start the job
                $job = Start-Job -ScriptBlock $jobScriptBlock -ArgumentList $dns, $testDomain, $recordType, $Timeout, $TestCount
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
    foreach ($dns in $filteredDnsProviders) {
        Write-ColoredMessage "`nTesting $($dns.Name)..." -Color Yellow
        
        # Test each domain
        foreach ($testDomain in $testDomains) {
            if ($testDomains.Count -gt 1) {
                Write-ColoredMessage "  Domain: $testDomain" -Color Cyan
            }
            
            foreach ($recordType in $recordTypes) {
                $result = Test-DNS -dnsIP $dns.IP -domain $testDomain -recordType $recordType -category $dns.Category -providerName $dns.Name
                
                # Run additional tests if enabled and main test succeeded
                if ($result.Status -eq "Success") {
                    # Test IPv6 support
                    if (-not $SkipIPv6Test) {
                        $ipv6Test = Test-IPv6Support -dnsIP $dns.IP -domain $testDomain -timeout $result.ActualTimeout
                        $result.IPv6Support = $ipv6Test.Success
                    }
                    
                    # Test DNSSEC support (only once per DNS, not per domain/record)
                    if (-not $SkipDNSSECTest -and $null -eq $result.DNSSECSupport) {
                        $dnssecTest = Test-DNSSECSupport -dnsIP $dns.IP -timeout $result.ActualTimeout
                        $result.DNSSECSupport = $dnssecTest.DNSSECSupported
                    }
                    
                    # Verify response quality
                    if (-not $SkipResponseVerification) {
                        $qualityTest = Test-ResponseQuality -dnsIP $dns.IP -domain $testDomain -recordType $recordType -timeout $result.ActualTimeout
                        if ($qualityTest.Success) {
                            $result.ResponseQuality = $qualityTest.Quality.IsComplete
                        }
                    }
                }
                
                # Update persistent tracking
                if (-not $DisablePersistentTracking) {
                    $failed = ($result.Status -eq "Error")
                    Update-PersistentTracking -History $global:PersistentHistory -DnsIP $dns.IP -Failed $failed
                }
                
                $results += [PSCustomObject]@{
                    Provider = $dns.Name
                    IP = $dns.IP
                    Category = $dns.Category
                    Domain = $testDomain
                    ResponseTime = if ($result.Status -eq "Error") { "Timeout" } else { "$($result.ResponseTime) ms" }
                    Status = $result.Status
                    Jitter = if ($result.Status -eq "Error") { "N/A" } else { "$($result.Jitter) ms" }
                    RecordType = $result.RecordType
                    SuccessRate = if ($result.Status -eq "Error") { 0 } else { $result.SuccessRate }
                    IPv6 = if ($null -eq $result.IPv6Support) { "N/A" } elseif ($result.IPv6Support) { "✓" } else { "✗" }
                    DNSSEC = if ($null -eq $result.DNSSECSupport) { "N/A" } elseif ($result.DNSSECSupport) { "✓" } else { "✗" }
                    Quality = if ($null -eq $result.ResponseQuality) { "N/A" } elseif ($result.ResponseQuality) { "✓" } else { "✗" }
                }
            }
        }
        
        # QuickTest early exit: Stop if we have enough good DNS servers
        if ($QuickTest) {
            $successfulResults = $results | Where-Object { $_.Status -eq "Success" }
            $successfulByCategory = $successfulResults | Group-Object -Property Category
            
            # Check if we have enough successful DNS per category
            $egyptianCount = ($successfulByCategory | Where-Object { $_.Name -eq "Egyptian" })
            $globalCount = ($successfulByCategory | Where-Object { $_.Name -eq "Global" })
            
            $hasEnoughEgyptian = if ($egyptianCount) { $egyptianCount.Count -ge 4 } else { $false }
            $hasEnoughGlobal = if ($globalCount) { $globalCount.Count -ge 10 } else { $false }
            $hasEnoughControlD = ($successfulResults | Where-Object { $_.Category -eq "ControlD" }).Count -ge 2
            
            # If we have enough from each category, stop testing
            if ($hasEnoughEgyptian -and $hasEnoughGlobal -and $hasEnoughControlD) {
                Write-ColoredMessage "`nQuickTest: Found sufficient reliable DNS servers, stopping early..." -Color Cyan
                break
            }
        }
        
        # After testing each DNS provider, check if THIS specific one should be removed
        if (-not $DisableFailureRemoval -or $AggressiveMode) {
            $shouldRemoveThis = Test-DnsRemoval -DnsIP $dns.IP -ProviderName $dns.Name -FailureThreshold $FailureThreshold -MaxFailureRate $MaxFailureRate
            
            if ($AggressiveMode) {
                $key = "$($dns.IP)|$($dns.Name)"
                if ($global:DnsFailureTracker.ContainsKey($key) -and $global:DnsFailureTracker[$key] -gt 0 -and $global:DnsSuccessTracker[$key] -eq 0) {
                    $shouldRemoveThis = $true
                }
            }
            
            if ($shouldRemoveThis) {
                $key = "$($dns.IP)|$($dns.Name)"
                $failures = if ($global:DnsFailureTracker.ContainsKey($key)) { $global:DnsFailureTracker[$key] } else { 0 }
                $successes = if ($global:DnsSuccessTracker.ContainsKey($key)) { $global:DnsSuccessTracker[$key] } else { 0 }
                $totalTests = $failures + $successes
                $failureRate = if ($totalTests -gt 0) { [math]::Round(($failures / $totalTests) * 100, 1) } else { 100 }
                
                # Update persistent tracking for this failure
                if (-not $DisablePersistentTracking) {
                    Update-PersistentTracking -History $global:PersistentHistory -DnsIP $dns.IP -Failed $true
                }
                
                $global:RemovedDnsProviders += [PSCustomObject]@{
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
        $failedTests = ($providerResults | Where-Object { $_.Status -eq "Error" -or $_.SuccessRate -eq 0 -or $_.ResponseTime -eq "Timeout" }).Count
        
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
            $global:RemovedDnsProviders += [PSCustomObject]@{
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
Write-ColoredMessage "`nFiltering out DNS providers that failed all tests..." -Color Yellow
$originalCount = $results.Count
$filteredResults = Remove-CompletelyFailedDNS -ResultsData $results
$removedCount = $originalCount - $filteredResults.Count

if ($removedCount -gt 0) {
    Write-ColoredMessage "Filtered out $removedCount results from DNS providers that failed all tests." -Color Yellow
    $results = $filteredResults
}

# Check if we have any valid results after filtering
if ($results.Count -eq 0) {
    Write-ColoredMessage "`nNo valid DNS results remain after filtering. All tested DNS servers failed completely." -Color Red
    Write-ColoredMessage "This might indicate a network connectivity issue. Please check your internet connection and try again." -Color Red
    exit 1
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
            $sortedResults = $typeResults | 
                Sort-Object { if ($_.ResponseTime -eq "Timeout" -or $_.ResponseTime -eq "Error") { [double]::MaxValue } else { [double]($_.ResponseTime -replace ' ms$', '') } }
            
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
    $sortedResults = $results | 
        Sort-Object { if ($_.ResponseTime -eq "Timeout" -or $_.ResponseTime -eq "Error") { [double]::MaxValue } else { [double]($_.ResponseTime -replace ' ms$', '') } }
    
    # Apply top results filter if specified
    if ($TopResults -gt 0) {
        $sortedResults = $sortedResults | Select-Object -First $TopResults
        Write-ColoredMessage "Showing top $TopResults fastest DNS providers:" -Color Gray
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
            Expression = { if ($_.Status -eq "Error") { "0%" } else { "$([math]::Round($_.SuccessRate))%" } }
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
        [string]$RecordType = "A"
    )
    
    $filteredResults = $DNSResults | Where-Object { 
        $_.Status -eq "Success" -and $_.RecordType -eq $RecordType -and $_.Category -eq $Category
    }
    
    if ($filteredResults.Count -eq 0) {
        return $null
    }

    # Score DNS providers based on response time, jitter and success rate
    # Lower is better: (response time * 0.6) + (jitter * 0.2) - (success rate * 0.2)
    $scoredDNS = $filteredResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        
        # Calculate score, weighted by importance
        $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        
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
        [string]$RecordType = "A"
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
        $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        
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
        $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        
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
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        
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

function Get-BestSameProviderPair {
    <#
    .SYNOPSIS
    Gets the best DNS pair from the same provider (e.g., Quad9 + Quad9 Secondary, NOT Quad9 + Quad9 Unsecured)
    Only matches strict primary/secondary pairs, not different variants of the same provider
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
    
    # Score each DNS
    $scoredDNS = $filteredResults | ForEach-Object {
        $responseTime = [double]($_.ResponseTime -replace ' ms$', '')
        $jitter = if ($_.Jitter -eq "N/A") { 0 } else { [double]($_.Jitter -replace ' ms$', '') }
        $successRate = [double]($_.SuccessRate)
        $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        
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
        [string]$RecordType = "A"
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
        $score = ($responseTime * 0.6) + ($jitter * 0.2) - ($successRate * 0.02)
        
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
        $bestPairs["${category}_${recordType}"] = Get-BestDNSPair -DNSResults $results -Category $category -RecordType $recordType
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
    $bestMixedPair = Get-BestMixedPair -DNSResults $results -RecordType $recordType
    $bestOverallPair = Get-BestOverallPair -DNSResults $results -RecordType $recordType
    $mostReliablePair = Get-MostReliablePair -DNSResults $results -RecordType $recordType
    $lowLatencyPair = Get-LowLatencyPair -DNSResults $results -RecordType $recordType
    $bestSameProviderPair = Get-BestSameProviderPair -DNSResults $results -RecordType $recordType
    $bestSameProviderPairGlobal = Get-BestSameProviderPairGlobal -DNSResults $results -RecordType $recordType
    
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
    
    # Option 7: Best Same Provider Pair
    Write-ColoredMessage "`n[7] Best Same-Provider Configuration (Any):" -Color Yellow
    if ($bestSameProviderPair) {
        Write-Host "    Provider:  " -NoNewline -ForegroundColor White
        Write-Host "$($bestSameProviderPair.ProviderName)" -ForegroundColor Magenta
        
        Write-Host "    Primary:   " -NoNewline -ForegroundColor White
        Write-Host "$($bestSameProviderPair.Primary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPair.Primary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPair.Primary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPair.Primary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPair.Primary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-Host "    Secondary: " -NoNewline -ForegroundColor White
        Write-Host "$($bestSameProviderPair.Secondary.IP)" -NoNewline -ForegroundColor Cyan
        Write-Host " (" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPair.Secondary.Provider)" -NoNewline -ForegroundColor Magenta
        Write-Host ") - " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPair.Secondary.ResponseTime)" -NoNewline -ForegroundColor Green
        Write-Host " (Jitter: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPair.Secondary.Jitter)" -NoNewline -ForegroundColor Yellow
        Write-Host ") [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$($bestSameProviderPair.Secondary.Category)" -NoNewline -ForegroundColor Blue
        Write-Host "]" -ForegroundColor DarkGray
        
        Write-ColoredMessage "    ✓ Pro: Unified infrastructure, consistent performance, proper redundancy" -Color DarkGreen
        Write-ColoredMessage "    ✗ Con: Single provider dependency (no diversity)" -Color DarkYellow
        Write-Host "    Stats: Avg Score: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($bestSameProviderPair.AverageScore, 2))" -NoNewline -ForegroundColor Cyan
        Write-Host " | Avg Latency: " -NoNewline -ForegroundColor White
        Write-Host "$([math]::Round($bestSameProviderPair.AverageLatency, 2)) ms" -ForegroundColor Cyan
    } else {
        Write-ColoredMessage "    No valid same-provider pair found" -Color Red
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
    Write-ColoredMessage "`nNo valid recommendations available." -Color Red
}

# Add IPv6, DNSSEC, and Quality statistics summary
Write-ColoredMessage "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan
Write-ColoredMessage "ADVANCED FEATURES SUMMARY:" -Color Cyan
Write-ColoredMessage "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Color Cyan

if (-not $SkipIPv6Test -or -not $SkipDNSSECTest -or -not $SkipResponseVerification) {
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
} else {
    Write-ColoredMessage "`nAdvanced tests disabled. Use -TestIPv6, -TestDNSSEC, or -VerifyResponses to enable." -Color Gray
}

# Store the best choice for script generation
if ($recommendations.Count -gt 0) {
    $script:RecommendedPair = $recommendations[0].Pair
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
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        
        $results | Export-Csv -Path $filename -NoTypeInformation
        Write-ColoredMessage "`nResults exported to $filename" -Color Green
    } catch {
        Write-ColoredMessage "Error exporting results: $_" -Color Red
    }
}

# Determine overall best DNS pair for configuration
Write-ColoredMessage "`n`nCommands to set DNS on your computer:" -Color Cyan
Write-ColoredMessage "======================================" -Color Cyan

# Use the recommended pair from the analysis above
if ($script:RecommendedPair -and $script:RecommendedPair.Primary -and $script:RecommendedPair.Secondary) {
    $bestOverallPair = $script:RecommendedPair
    
    Write-ColoredMessage "`nUsing Recommended Configuration:" -Color Magenta
    Write-ColoredMessage "Primary:   $($bestOverallPair.Primary.IP) ($($bestOverallPair.Primary.Provider))" -Color Green
    Write-ColoredMessage "Secondary: $($bestOverallPair.Secondary.IP) ($($bestOverallPair.Secondary.Provider))" -Color Green
    
    Write-ColoredMessage "`nWindows PowerShell (Run as Administrator):" -Color Yellow
    Write-ColoredMessage "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet*' -ServerAddresses ('$($bestOverallPair.Primary.IP)','$($bestOverallPair.Secondary.IP)')" -Color White
    
    Write-ColoredMessage "`nUbuntu/Debian (Run with sudo):" -Color Yellow
    Write-ColoredMessage "sudo bash -c 'echo nameserver $($bestOverallPair.Primary.IP) > /etc/resolv.conf'" -Color White
    Write-ColoredMessage "sudo bash -c 'echo nameserver $($bestOverallPair.Secondary.IP) >> /etc/resolv.conf'" -Color White
    
    Write-ColoredMessage "`nMacOS:" -Color Yellow
    Write-ColoredMessage "networksetup -setdnsservers Wi-Fi $($bestOverallPair.Primary.IP) $($bestOverallPair.Secondary.IP)" -Color White
    
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
                New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
                
                $windowsScript | Out-File -FilePath (Join-Path $scriptDir "configure-dns-windows.ps1") -Encoding UTF8
                $linuxScript | Out-File -FilePath (Join-Path $scriptDir "configure-dns-linux.sh") -Encoding UTF8
                $macScript | Out-File -FilePath (Join-Path $scriptDir "configure-dns-macos.sh") -Encoding UTF8
                
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

# Display removed DNS providers if any
if ($global:RemovedDnsProviders.Count -gt 0) {
    Write-ColoredMessage "`n`nRemoved DNS Providers (Due to Failures)" -Color Red
    Write-ColoredMessage "======================================" -Color Red
    
    $global:RemovedDnsProviders | Format-Table -AutoSize -Property @{
        Label = "Provider"
        Expression = { $_.Name }
        Width = 30
    }, @{
        Label = "IP Address"
        Expression = { $_.IP }
        Width = 20
    }, @{
        Label = "Category"
        Expression = { $_.Category }
        Width = 15
    }, @{
        Label = "Failures"
        Expression = { $_.Failures }
        Width = 10
    }, @{
        Label = "Successes"
        Expression = { $_.Successes }
        Width = 10
    }, @{
        Label = "Failure Rate"
        Expression = { $_.FailureRate }
        Width = 12
    }, @{
        Label = "Reason"
        Expression = { $_.Reason }
        Width = 20
    } | Out-Host
    
    Write-ColoredMessage "Total removed: $($global:RemovedDnsProviders.Count) DNS provider(s)" -Color Yellow
}

# Save persistent tracking history
if (-not $DisablePersistentTracking) {
    Save-PersistentTracking -History $global:PersistentHistory
    
    # Show summary of newly failed DNS servers
    $newlyFailed = @()
    $approachingBlacklist = @()
    
    foreach ($dns in $global:PersistentHistory.Keys) {
        $record = $global:PersistentHistory[$dns]
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
    
    if ($approachingBlacklist.Count -gt 0) {
        Write-ColoredMessage "`nDNS servers with recorded failures (will be blacklisted after $PersistentFailureThreshold total failures):" -Color Yellow
        $approachingBlacklist | Sort-Object -Property Failures -Descending | ForEach-Object {
            Write-ColoredMessage "  $($_.IP) - Failed $($_.Failures) time(s), $($_.Remaining) more failure(s) until blacklist" -Color Yellow
        }
    }
    
    if ($newlyFailed.Count -gt 0) {
        Write-ColoredMessage "`nDNS servers blacklisted (will be excluded from future tests):" -Color Red
        $newlyFailed | ForEach-Object {
            Write-ColoredMessage "  $_" -Color Red
        }
    }
    
    Write-ColoredMessage "`nPersistent tracking history saved. Use -ShowTrackingStats to view full statistics." -Color Green
}

Write-ColoredMessage "`nDNS Performance Test completed." -Color Cyan
