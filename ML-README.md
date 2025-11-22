# DNS Benchmark - Machine Learning System

## Quick Start

The ML system is **automatically enabled** when you run `Test-DNSProviders.ps1`. No configuration needed!

## What It Does

### Learns From Every Run
- Records DNS performance (speed, reliability, jitter)
- Tracks which DNS pairs work best
- Identifies performance trends (improving/degrading servers)

### Optimizes Future Tests  
- Tests best-performing DNS servers first
- Recommends optimal DNS pairs based on history
- Saves time in QuickTest mode

### Adapts to Your Network
- Learns which DNS works best for YOUR specific location
- Adjusts to your network conditions over time
- Builds a personalized "best of the best" list

## Scoring System

**Lower scores = Better performance**

The ML algorithm evaluates DNS servers using:
- **Response Time (40%)**: How fast queries resolve
- **Success Rate (30%)**: How reliable the server is
- **Jitter (15%)**: Connection consistency
- **Performance Trend (10%)**: Is it getting better or worse?
- **Advanced Features (5%)**: IPv6, DNSSEC support

## How It Learns

### Run 1: Initial Data Collection
```
Testing all DNS providers...
✓ Results collected and saved
```

### Run 2-5: Pattern Detection
```
ML Optimization: Prioritizing top-performing DNS servers from 3 historical runs...
✓ Performance trends detected
✓ Best pairs identified
```

### Run 10+: Smart Recommendations
```
ML Recommended Pair: Cloudflare (1.1.1.1) + Cloudflare (1.0.0.1)
  Based on 8 tests, Avg Score: 12.34
✓ Highly accurate predictions
✓ Significant time savings
```

## Data Files

Three files store the learning data:

### 1. `dns-ml-data.json`
Complete ML training data with all historical performance metrics

### 2. `dns-ml-recommendations.txt`  
Human-readable report showing:
- Top 10 best DNS servers
- Top 5 best DNS pairs
- Performance trends (↑ Improving, ↓ Degrading, → Stable)

### 3. `dns-failure-history.json`
Tracks failures to blacklist unreliable servers

## View Your ML Insights

```powershell
# View the ML recommendations report
Get-Content dns-ml-recommendations.txt

# Check ML statistics
.\Test-DNSProviders.ps1 -ShowTrackingStats
```

## Configuration Types Tracked

The ML system learns the best configurations for different scenarios:

1. **Best Overall**: Fastest pair regardless of provider
2. **Same Provider Global**: Both from same global provider (reliability)
3. **Mixed**: One Egyptian + One Global (balanced approach)
4. **Category-Specific**: Best within each category

## Example Output

```
========================================
TOP 10 INDIVIDUAL DNS SERVERS
========================================

Cloudflare (1.1.1.1)
  Category: Global
  ML Score: 12.34 (lower is better)
  Avg Response: 18.5 ms
  Avg Success Rate: 98.2%
  Tests: 15
  Trend: ↑ Improving

Google DNS (8.8.8.8)
  Category: Global
  ML Score: 15.67
  Avg Response: 22.1 ms
  Avg Success Rate: 99.1%
  Tests: 15
  Trend: → Stable

========================================
TOP 5 DNS PAIR CONFIGURATIONS
========================================

Primary: Cloudflare (1.1.1.1)
Secondary: Cloudflare (1.0.0.1)
  Type: Same Provider Global
  ML Score: 13.45
  Tests: 8
  Best Score: 11.23
  Times Recommended: 12
```

## Benefits

### Time Savings
- QuickTest mode tests only top performers
- Skip unreliable servers automatically
- Get results faster each run

### Better Results
- Recommends DNS pairs proven to work in your location
- Identifies degrading servers before they fail
- Adapts to changing network conditions

### Personalized
- Learns YOUR specific network characteristics
- Egyptian network optimizations
- Time-of-day patterns (future enhancement)

## Reset ML Learning

Start fresh if needed:

```powershell
# Delete all ML and tracking data
Remove-Item dns-ml-data.json -ErrorAction SilentlyContinue
Remove-Item dns-failure-history.json -ErrorAction SilentlyContinue
Remove-Item dns-ml-recommendations.txt -ErrorAction SilentlyContinue

# Run with reset flag
.\Test-DNSProviders.ps1 -ResetTracking
```

## Technical Details

### Scoring Formula
```
Score = (ResponseTime × 0.40) + 
        (FailureRate × 0.30) + 
        (Jitter × 0.15) + 
        (TrendPenalty × 0.10) - 
        (FeatureBonus × 0.05)
```

### Trend Analysis
Uses linear regression on the last 10 test scores to calculate if performance is:
- **Improving** (positive trend): Scores getting lower over time
- **Stable** (flat trend): Consistent performance
- **Degrading** (negative trend): Scores getting higher over time

### Reliability Multipliers
- **Consecutive failures**: Score increases by 20% per failure
- **Consecutive successes** (5+): Score reduced by 10%

## Privacy & Security

- All data stored **locally** on your machine
- No external network calls
- No telemetry or data collection
- Completely offline ML system

## Troubleshooting

### "ML Scorer module not available"
**Cause**: `DNS-ML-Scorer.ps1` not found  
**Fix**: Ensure both scripts are in the same directory

### Unexpected Recommendations
- ML requires at least **2 test runs** before making recommendations
- Recommendations are personalized to YOUR network
- Different results than others is EXPECTED (that's the point!)

### Want to Understand More?
Check the detailed implementation guide in the script comments.

---

**The more you run it, the smarter it gets!** 🧠

Run the test regularly to build a comprehensive performance database.
