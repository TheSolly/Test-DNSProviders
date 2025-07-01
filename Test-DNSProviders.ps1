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
    
    [Parameter(HelpMessage="Remove consistently failing DNS servers from results")]
    [switch]$RemoveFailingDNS,
    
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
    
    [Parameter(HelpMessage="Test using alternative domains (google.com, facebook.com, etc.)")]
    [switch]$AlternateDomains,
    
    [Parameter(HelpMessage="Generate network configuration scripts for Windows, Linux, and macOS")]
    [switch]$GenerateScripts,
      [Parameter(HelpMessage="Show warnings for problematic DNS servers")]
    [switch]$ShowWarnings,
    
    [Parameter(HelpMessage="Aggressive mode: Remove failing DNS servers immediately")]
    [switch]$AggressiveMode,
    
    [Parameter(HelpMessage="Quick test mode: Reduce test count for faster results")]
    [switch]$QuickTest
)

# Check if required modules are available
if (-not (Get-Command "Resolve-DnsName" -ErrorAction SilentlyContinue)) {
    Write-Host "The required cmdlet 'Resolve-DnsName' is not available on your system." -ForegroundColor Red
    Write-Host "This script requires Windows PowerShell 5.1 or later with the DnsClient module." -ForegroundColor Red
    exit 1
}

# Global variables for failure tracking
$global:DnsFailureTracker = @{}
$global:DnsSuccessTracker = @{}
$global:RemovedDnsProviders = @()

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
        [bool]$ShowWarnings
    )
    
    $filteredProviders = @()
    
    foreach ($dns in $DnsProviders) {
        $shouldRemove = Test-DnsRemoval -DnsIP $dns.IP -ProviderName $dns.Name -FailureThreshold $FailureThreshold -MaxFailureRate $MaxFailureRate
        
        if ($shouldRemove) {
            $key = "$($dns.IP)|$($dns.Name)"
            $failures = $global:DnsFailureTracker[$key]
            $successes = $global:DnsSuccessTracker[$key]
            $totalTests = $failures + $successes
            $failureRate = if ($totalTests -gt 0) { [math]::Round(($failures / $totalTests) * 100, 1) } else { 100 }
            
            $global:RemovedDnsProviders += [PSCustomObject]@{
                Name = $dns.Name
                IP = $dns.IP
                Category = $dns.Category
                Failures = $failures
                Successes = $successes
                FailureRate = "$failureRate%"
                Reason = if ($failures -ge $FailureThreshold -and $successes -eq 0) { "Consecutive failures" } else { "High failure rate" }
            }
            
            if ($ShowWarnings) {
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
$testDomain = $Domain
if ($AlternateDomains) {
    $testDomains = @("google.com", "facebook.com", "youtube.com", "amazon.com", "microsoft.com")
    $testDomain = $testDomains | Get-Random
    Write-ColoredMessage "Using alternate domain: $testDomain" -Color Yellow
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
            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
        }
        
        $result = Receive-Job $resolveJob
        Remove-Job $resolveJob -Force
        
        if (-not $result.Success) {
            Write-ColoredMessage "Failed ($($result.Error))" -Color Red
            Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
            return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
        }
    } catch {
        Write-ColoredMessage "Failed (error: $_)" -Color Red
        Update-DnsTracker -DnsIP $dnsIP -ProviderName $providerName -Success $false
        return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
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
                    CurrentOperation = "IP: $dnsIP ($recordType) - Timeout: ${currentTimeout}s"
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
                Write-Host "Error in test $i for $dnsIP ($recordType): $_" -ForegroundColor Yellow
            }
            continue
        }
    }
    
    if ($DetailedOutput) {
        Write-Progress -Activity "Testing DNS Server $dnsIP" -Completed
    }
    
    if ($successCount -eq 0) {
        return @{Status = "Error"; ResponseTime = 0; Jitter = 0; RecordType = $recordType}
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
    }
}

# Clear screen and show header
Clear-Host
Write-ColoredMessage "DNS Performance Test" -Color Cyan
Write-ColoredMessage "===================" -Color Cyan
Write-ColoredMessage "Testing DNS servers response time for: " -Color Yellow -NoNewline
Write-ColoredMessage $testDomain -Color Green
Write-ColoredMessage "Mode: $(if ($Parallel) { 'Parallel' } else { 'Sequential' })" -Color Yellow
Write-ColoredMessage "Testing $(if ($Category -eq 'All') { 'all' } else { $Category }) DNS providers" -Color Yellow
Write-ColoredMessage "Record types: $($recordTypes -join ', ')" -Color Yellow
Write-ColoredMessage "Tests per DNS: $TestCount with $Timeout second timeout" -Color Yellow
if ($AdaptiveTimeout) {
    Write-ColoredMessage "Adaptive timeout enabled: Egyptian DNS timeout = $EgyptianTimeout seconds" -Color Yellow
}
if ($RemoveFailingDNS) {
    Write-ColoredMessage "Failure removal enabled: Max failure rate = $([math]::Round($MaxFailureRate * 100, 1))%, Threshold = $FailureThreshold consecutive failures" -Color Yellow
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
        
        foreach ($recordType in $recordTypes) {
            $result = Test-DNS -dnsIP $dns.IP -domain $testDomain -recordType $recordType -category $dns.Category -providerName $dns.Name
            
            $results += [PSCustomObject]@{
                Provider = $dns.Name
                IP = $dns.IP
                Category = $dns.Category
                ResponseTime = if ($result.Status -eq "Error") { "Timeout" } else { "$($result.ResponseTime) ms" }
                Status = $result.Status
                Jitter = if ($result.Status -eq "Error") { "N/A" } else { "$($result.Jitter) ms" }
                RecordType = $result.RecordType
                SuccessRate = if ($result.Status -eq "Error") { 0 } else { $result.SuccessRate }
            }
        }
        
        # After testing each DNS provider, check if we should remove failing ones
        if ($RemoveFailingDNS) {
            $filteredDnsProviders = Remove-FailingDnsProviders -DnsProviders $filteredDnsProviders -FailureThreshold $FailureThreshold -MaxFailureRate $MaxFailureRate -ShowWarnings $ShowWarnings
        }
    }
}

# Check if we have any results
if ($results.Count -eq 0) {
    Write-ColoredMessage "`nNo results were gathered. Please check your network connection and try again." -Color Red
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
                    Width = 30
                }, @{
                    Label = "IP Address"
                    Expression = { $_.IP }
                    Width = 20
                }, @{
                    Label = "Response Time"
                    Expression = { $_.ResponseTime }
                    Width = 15
                }, @{
                    Label = "Jitter"
                    Expression = { $_.Jitter }
                    Width = 10
                }, @{
                    Label = "Success Rate"
                    Expression = { if ($_.Status -eq "Error") { "0%" } else { "$($_.SuccessRate)%" } }
                    Width = 12
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
            Width = 30
        }, @{
            Label = "IP Address"
            Expression = { $_.IP }
            Width = 20
        }, @{
            Label = "Response Time"
            Expression = { $_.ResponseTime }
            Width = 15
        }, @{
            Label = "Jitter"
            Expression = { $_.Jitter }
            Width = 10
        }, @{
            Label = "Success Rate"
            Expression = { if ($_.Status -eq "Error") { "0%" } else { "$([math]::Round($_.SuccessRate))%" } }
            Width = 12
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
    }      # Get statistics for each category
    $egyptianStats = $categoryStats["Egyptian_${recordType}"]
    $globalStats = $categoryStats["Global_${recordType}"]
    
    # Get best pairs for each category
    $bestEgyptianPair = $bestPairs["Egyptian_${recordType}"]
    $bestGlobalPair = $bestPairs["Global_${recordType}"]# Display Egyptian results
    Write-ColoredMessage "`nBest Egyptian DNS Configuration:" -Color Yellow
    if ($bestEgyptianPair -and $bestEgyptianPair.Primary -and $bestEgyptianPair.Secondary) {
        Write-ColoredMessage "Primary:   $($bestEgyptianPair.Primary.IP) ($($bestEgyptianPair.Primary.Provider)) - $($bestEgyptianPair.Primary.ResponseTime) (Jitter: $($bestEgyptianPair.Primary.Jitter))" -Color Green
        Write-ColoredMessage "Secondary: $($bestEgyptianPair.Secondary.IP) ($($bestEgyptianPair.Secondary.Provider)) - $($bestEgyptianPair.Secondary.ResponseTime) (Jitter: $($bestEgyptianPair.Secondary.Jitter))" -Color Green
        
        if ($egyptianStats) {
            Write-ColoredMessage "Statistics:" -Color Gray
            Write-ColoredMessage "  Min: $([math]::Round($egyptianStats.Min, 2)) ms" -Color Gray
            Write-ColoredMessage "  Max: $([math]::Round($egyptianStats.Max, 2)) ms" -Color Gray
            Write-ColoredMessage "  Avg: $([math]::Round($egyptianStats.Avg, 2)) ms" -Color Gray
            Write-ColoredMessage "  Avg Jitter: $([math]::Round($egyptianStats.AvgJitter, 2)) ms" -Color Gray
            Write-ColoredMessage "  Successful Tests: $($egyptianStats.Count)" -Color Gray
        }    } else {
        Write-ColoredMessage "No valid Egyptian DNS pair found for $recordType records." -Color Red
    }

    # Display Global results
    Write-ColoredMessage "`nBest Global DNS Configuration:" -Color Yellow
    if ($bestGlobalPair -and $bestGlobalPair.Primary -and $bestGlobalPair.Secondary) {
        Write-ColoredMessage "Primary:   $($bestGlobalPair.Primary.IP) ($($bestGlobalPair.Primary.Provider)) - $($bestGlobalPair.Primary.ResponseTime) (Jitter: $($bestGlobalPair.Primary.Jitter))" -Color Green
        Write-ColoredMessage "Secondary: $($bestGlobalPair.Secondary.IP) ($($bestGlobalPair.Secondary.Provider)) - $($bestGlobalPair.Secondary.ResponseTime) (Jitter: $($bestGlobalPair.Secondary.Jitter))" -Color Green
        
        if ($globalStats) {
            Write-ColoredMessage "Statistics:" -Color Gray
            Write-ColoredMessage "  Min: $([math]::Round($globalStats.Min, 2)) ms" -Color Gray
            Write-ColoredMessage "  Max: $([math]::Round($globalStats.Max, 2)) ms" -Color Gray
            Write-ColoredMessage "  Avg: $([math]::Round($globalStats.Avg, 2)) ms" -Color Gray
            Write-ColoredMessage "  Avg Jitter: $([math]::Round($globalStats.AvgJitter, 2)) ms" -Color Gray
            Write-ColoredMessage "  Successful Tests: $($globalStats.Count)" -Color Gray
        }
    } else {
        Write-ColoredMessage "No valid Global DNS pair found for $recordType records." -Color Red
    }    # Overall recommendation
    Write-ColoredMessage "`nRecommendation for $recordType records:" -Color Cyan
    $validStats = @()
    if ($egyptianStats) { $validStats += @{Name = "Egyptian"; Avg = $egyptianStats.Avg; Jitter = $egyptianStats.AvgJitter; Pair = $bestEgyptianPair} }
    if ($globalStats) { $validStats += @{Name = "Global"; Avg = $globalStats.Avg; Jitter = $globalStats.AvgJitter; Pair = $bestGlobalPair} }
    
    if ($validStats.Count -gt 0) {
        # Sort categories by average response time (lower is better)
        $bestCategoryStats = $validStats | Sort-Object Avg | Select-Object -First 1
        Write-ColoredMessage "Use $($bestCategoryStats.Name) DNS configuration for best performance (Avg: $([math]::Round($bestCategoryStats.Avg, 2)) ms, Jitter: $([math]::Round($bestCategoryStats.Jitter, 2)) ms)" -Color Green
    } else {
        Write-ColoredMessage "No valid DNS configurations found for $recordType records." -Color Red
    }
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
Write-ColoredMessage "`nCommands to set DNS on your computer:" -Color Cyan
Write-ColoredMessage "=================================" -Color Cyan

# Define record type to use for overall recommendation (default to A records)
$primaryRecordType = "A"

# Get DNS stats for each category with this record type
$egyptianStatsForOverall = $categoryStats["Egyptian_${primaryRecordType}"]
$globalStatsForOverall = $categoryStats["Global_${primaryRecordType}"]

# Get best pairs for this record type
$bestEgyptianPairForOverall = $bestPairs["Egyptian_${primaryRecordType}"]
$bestGlobalPairForOverall = $bestPairs["Global_${primaryRecordType}"]

# Get best overall DNS pair
$validStats = @()
if ($egyptianStatsForOverall) { 
    $validStats += @{
        Name = "Egyptian"
        Avg = $egyptianStatsForOverall.Avg
        Jitter = $egyptianStatsForOverall.AvgJitter
        Pair = $bestEgyptianPairForOverall
    }
}
if ($globalStatsForOverall) { 
    $validStats += @{
        Name = "Global"
        Avg = $globalStatsForOverall.Avg
        Jitter = $globalStatsForOverall.AvgJitter
        Pair = $bestGlobalPairForOverall
    }
}

# Display recommendations based on available results
if ($validStats.Count -gt 0) {
    # Sort by performance (lower average response time is better)
    $bestOverallStats = $validStats | Sort-Object Avg | Select-Object -First 1
    $bestOverallPair = $bestOverallStats.Pair
    $providerType = $bestOverallStats.Name
    
    if ($bestOverallPair -and $bestOverallPair.Primary -and $bestOverallPair.Secondary) {
        Write-ColoredMessage "`nRecommended DNS Configuration ($providerType):" -Color Magenta
        Write-ColoredMessage "`nWindows PowerShell:" -Color Yellow
        Write-ColoredMessage "Set-DnsClientServerAddress -InterfaceAlias 'Ethernet*' -ServerAddresses ('$($bestOverallPair.Primary.IP)','$($bestOverallPair.Secondary.IP)')" -Color White
        
        Write-ColoredMessage "`nUbuntu/Debian:" -Color Yellow
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
        Write-ColoredMessage "`nCould not determine a valid DNS configuration from test results." -Color Red
    }
} else {    Write-ColoredMessage "`nNo valid DNS configuration found. All tested DNS servers failed or timed out." -Color Red
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

Write-ColoredMessage "`nDNS Performance Test completed." -Color Cyan
