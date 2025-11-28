# DNS Benchmark

A powerful PowerShell script for benchmarking DNS providers and finding the fastest and most reliable DNS servers with machine learning optimization.

## Features

- **Machine Learning Optimization**: Learns from historical test results to prioritize best-performing DNS servers
- **Jitter-Aware Scoring**: Composite scoring that considers both speed and consistency (critical for gaming/streaming)
- **Gaming/Streaming Tests**: EDNS0 and TCP fallback support testing
- Tests multiple DNS providers including Egyptian, Global, and Control D DNS servers
- Measures response time, jitter, and reliability
- Tests multiple DNS record types (A, AAAA, MX, TXT, NS)
- Supports parallel and sequential testing modes
- Provides detailed statistics and recommendations
- Generates configuration commands for Windows, Linux, and macOS
- Persistent tracking of DNS failures and performance trends
- Automatic blacklisting of consistently failing DNS servers

## Machine Learning Features

The script includes an advanced ML-based scoring system (`DNS-ML-Scorer.ps1`) that:

### Learning & Optimization
- **Tracks Historical Performance**: Records response time, success rate, jitter, and advanced features (IPv6, DNSSEC) for every DNS server
- **Calculates Performance Trends**: Uses regression analysis to identify improving or degrading DNS servers
- **Prioritizes Testing**: Automatically tests best-performing DNS servers first, saving time
- **Recommends Best Pairs**: Learns which DNS pair configurations perform best over time

### Scoring Algorithm
The ML system uses a weighted composite score (lower is better):
- **Response Time (40%)**: Average latency
- **Success Rate (30%)**: Reliability percentage
- **Jitter (15%)**: Connection consistency
- **Historical Trend (10%)**: Performance trajectory
- **Advanced Features (5%)**: IPv6, DNSSEC support

### Data Files
- `dns-ml-data.json`: ML training data (servers, pairs, scores, trends)
- `dns-ml-recommendations.txt`: Human-readable report of top performers
- `dns-failure-history.json`: Persistent failure tracking

## Usage

```powershell
# Basic usage (with ML optimization enabled by default)
.\Test-DNSProviders.ps1

# Test specific DNS categories
.\Test-DNSProviders.ps1 -Category Global     # Only test global DNS providers
.\Test-DNSProviders.ps1 -Category Egyptian   # Only test Egyptian DNS providers
.\Test-DNSProviders.ps1 -Category ControlD   # Only test Control D DNS providers

# Test with different parameters
.\Test-DNSProviders.ps1 -Parallel -MultiRecordTest -TestCount 10 -Timeout 5

# Export results to CSV
.\Test-DNSProviders.ps1 -ExportPath "C:\Temp\dns_results.csv"

# Quick test mode (⚡ FAST: 15-30 seconds - stops after finding 10 good DNS)
.\Test-DNSProviders.ps1 -QuickTest

# Quick test with specific domain (fastest way to get recommendations)
.\Test-DNSProviders.ps1 -QuickTest -Domain "psn.com"

# Quick test ALL DNS providers - no early exit (best for ML training)
.\Test-DNSProviders.ps1 -QuickTest -NoEarlyExit -Domain "psn.com"

# Gaming/Streaming optimized test (considers jitter, tests EDNS0 & TCP)
.\Test-DNSProviders.ps1 -SortByScore -JitterWeight 3.0 -TestEDNS0 -TestTCP

# Quick gaming test (fastest way to find best gaming DNS)
.\Test-DNSProviders.ps1 -QuickTest -SortByScore -JitterWeight 4.0 -TopResults 5

# View ML recommendations
Get-Content dns-ml-recommendations.txt

# Reset persistent tracking and start ML learning fresh
.\Test-DNSProviders.ps1 -ResetTracking
```

### Gaming & Streaming Optimization

For gaming and streaming, **jitter matters more than raw speed**! A DNS with slightly higher average response time but low jitter will provide better performance.

```powershell
# Recommended for gaming (prioritizes stability over speed)
.\Test-DNSProviders.ps1 -SortByScore -JitterWeight 4.0 -TestEDNS0 -TestTCP

# Recommended for streaming (balanced approach)
.\Test-DNSProviders.ps1 -SortByScore -JitterWeight 2.5 -TestEDNS0 -TestTCP
```

**See [JITTER-SCORING-GUIDE.md](JITTER-SCORING-GUIDE.md) for detailed explanation and examples.**

## How ML Learning Works

1. **First Run**: Tests all DNS servers normally, records performance data
2. **Subsequent Runs**: 
   - Displays ML-recommended DNS pair based on historical data
   - Tests best-performing servers first (saves time in QuickTest mode)
   - Updates ML model with new test results
   - Generates recommendations report

3. **Over Time**: 
   - The more you run the script, the smarter it gets
   - Identifies "best of the best" DNS configurations
   - Adapts to your network conditions and location
   - Automatically deprioritizes degrading servers

### Example ML Output
```
ML Optimization: Prioritizing top-performing DNS servers from 15 historical runs...
ML Recommended Pair: Cloudflare (1.1.1.1) + Cloudflare (1.0.0.1)
  Based on 8 tests, Avg Score: 12.34
```

## Requirements

- Windows PowerShell 5.1 or later
- DnsClient module
- Internet connectivity

## License

MIT
