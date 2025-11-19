# DNS Benchmark Script Improvements

## Overview
The `Test-DNSProviders.ps1` script has been significantly enhanced with persistent failure tracking and comprehensive DNS pairing recommendations.

## New Features

### 1. Persistent DNS Failure Tracking
- **Automatic Blacklisting**: DNS servers that fail repeatedly across multiple script runs are automatically blacklisted
- **JSON-Based Storage**: Failure history is stored in `dns-failure-history.json` for persistence
- **Configurable Threshold**: Default is 3 consecutive failures before blacklisting (adjustable via `-PersistentFailureThreshold`)
- **Smart Reset**: Success resets the failure count, preventing temporary issues from permanently blacklisting servers

### 2. New Parameters

#### `-PersistentTracking` (Default: Enabled)
Enables persistent failure tracking across script runs. DNS servers that consistently fail are remembered and excluded from future tests.

#### `-PersistentFailureThreshold` (Default: 3)
Number of consecutive script runs a DNS must fail before being blacklisted.

```powershell
# Set custom failure threshold
.\Test-DNSProviders.ps1 -PersistentFailureThreshold 5
```

#### `-ResetTracking`
Resets the persistent tracking history, removing all blacklisted DNS servers.

```powershell
# Clear failure history
.\Test-DNSProviders.ps1 -ResetTracking
```

#### `-ShowTrackingStats`
Displays detailed statistics about DNS failure tracking history.

```powershell
# View tracking statistics
.\Test-DNSProviders.ps1 -ShowTrackingStats

# View stats and run test
.\Test-DNSProviders.ps1 -ShowTrackingStats -Domain google.com
```

### 3. Enhanced DNS Pair Recommendations

The script now provides **6 different pairing options** with pros/cons for each:

#### [1] Best Egyptian DNS Configuration
- **Pro**: Local servers, potentially less censorship
- **Con**: May have reliability issues
- Best performing Egyptian DNS servers paired together

#### [2] Best Global DNS Configuration
- **Pro**: Highly reliable, global infrastructure
- **Con**: May be slower from Egypt
- Best performing global DNS servers paired together

#### [3] Best Mixed Configuration (Egyptian + Global)
- **Pro**: Balanced approach, failover between local and global
- **Con**: Performance varies by location
- One Egyptian + One Global server for redundancy

#### [4] Best Overall Performance (Any Category)
- **Pro**: Absolute best performance in testing
- **Con**: May prioritize speed over reliability
- The two fastest DNS servers regardless of category

#### [5] Most Reliable Configuration
- **Pro**: Highest success rate, most stable
- **Con**: May not be the fastest option
- DNS servers with the highest success rates

#### [6] Lowest Latency Configuration
- **Pro**: Fastest response times
- **Con**: May sacrifice reliability for speed
- DNS servers with the absolute lowest response times

### 4. Automatic Best Recommendation

The script automatically recommends the best configuration based on:
- Balanced scoring of speed, jitter, and reliability
- Prioritizes mixed configurations when available
- Falls back to best overall or category-specific pairs

## Usage Examples

### Basic Test with Tracking
```powershell
# Standard test (tracking enabled by default)
.\Test-DNSProviders.ps1

# Run multiple times to build failure history
.\Test-DNSProviders.ps1 -QuickTest
```

### View Tracking Statistics
```powershell
# See which DNS servers have been tracked
.\Test-DNSProviders.ps1 -ShowTrackingStats
```

### Reset and Start Fresh
```powershell
# Clear all tracking history
.\Test-DNSProviders.ps1 -ResetTracking

# Then run a new test
.\Test-DNSProviders.ps1
```

### Disable Persistent Tracking
```powershell
# Run without persistent tracking
.\Test-DNSProviders.ps1 -PersistentTracking:$false
```

### Customize Failure Threshold
```powershell
# Require 5 failures before blacklisting
.\Test-DNSProviders.ps1 -PersistentFailureThreshold 5
```

## How Persistent Tracking Works

1. **First Run**: All DNS servers are tested, failures are recorded
2. **Subsequent Runs**: Previously failed DNS servers get another chance
3. **After 3 Failures**: DNS server is automatically blacklisted and excluded from future tests
4. **On Success**: Failure count resets to 0, blacklist status removed

## Benefits

### Persistent Tracking
- **Faster Tests**: Eliminates time wasted on consistently failing DNS servers
- **More Accurate**: Focus on DNS servers that actually work in your location
- **Intelligent**: Temporary failures don't permanently blacklist servers
- **Transparent**: View full statistics with `-ShowTrackingStats`

### Enhanced Recommendations
- **Multiple Options**: Choose the configuration that best fits your needs
- **Informed Decisions**: See pros/cons for each pairing type
- **Flexibility**: Egyptian-only, Global-only, or Mixed configurations
- **Prioritized**: Automatic recommendation based on balanced criteria

## Configuration Scripts

The script generates platform-specific configuration scripts using the recommended DNS pair:

- **Windows**: `configure-dns-windows.ps1`
- **Linux**: `configure-dns-linux.sh`
- **macOS**: `configure-dns-macos.sh`

Use `-GenerateScripts` parameter to create these files.

## Troubleshooting

### All DNS Servers Blacklisted
```powershell
# Reset tracking and try again
.\Test-DNSProviders.ps1 -ResetTracking
```

### Want to See Full Statistics
```powershell
# View detailed tracking information
.\Test-DNSProviders.ps1 -ShowTrackingStats
```

### Persistent Tracking File Location
The tracking history is stored in:
```
dns-failure-history.json
```
Located in the same directory as the script.

## Migration from Previous Version

The enhanced script is fully backward compatible. Existing scripts and commands will continue to work. New features are opt-in or enabled by default with sensible defaults.

---

**Last Updated**: October 1, 2025
