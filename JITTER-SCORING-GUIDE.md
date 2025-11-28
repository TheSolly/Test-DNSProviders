# DNS Jitter-Aware Scoring Guide

## Overview

The script now supports **composite scoring** that considers both response time and jitter, which is critical for gaming and streaming applications.

## What is Jitter?

**Jitter** is the variance in response times. High jitter means inconsistent performance, which causes:
- Lag spikes in online gaming
- Buffering in video streaming
- Poor VoIP call quality
- Unstable connections

## Traditional vs Jitter-Aware Sorting

### Traditional Sorting (Response Time Only)
```powershell
.\Test-DNSProviders.ps1 -QuickTest -TopResults 10
```

**Result Example:**
```
Provider                    Response Time  Jitter
--------                    -------------  ------
TE-Data Primary            529.45 ms      79.15 ms  ⚠️ High jitter!
CleanBrowsing Adult Filter 560.57 ms      1.77 ms   ✓ Stable
Safe DNS                   613.35 ms      0.84 ms   ✓ Very stable
```

**Problem:** TE-Data appears "fastest" but has **79ms jitter** - terrible for gaming!

### Jitter-Aware Sorting (Composite Score)
```powershell
.\Test-DNSProviders.ps1 -QuickTest -TopResults 10 -SortByScore -JitterWeight 2.5
```

**Result Example:**
```
Provider                    Response Time  Jitter    Score
--------                    -------------  ------    -----
CleanBrowsing Adult Filter 560.57 ms      1.77 ms   565.00 ms    ✓ Best overall
TE-Data Primary            529.45 ms      79.15 ms  727.33 ms    ⚠️ Penalized for jitter
Safe DNS                   613.35 ms      0.84 ms   615.45 ms    ✓ 2nd best
```

**Better:** CleanBrowsing ranks higher despite being 31ms slower, because it's **much more stable**.

## Composite Score Formula

```
Composite Score = Response Time + (Jitter × Weight)
```

### Recommended Jitter Weights

| Use Case | Weight | Explanation |
|----------|--------|-------------|
| **Gaming** | 3.0-5.0 | Jitter matters MORE than speed; lag spikes ruin gameplay |
| **Streaming** | 2.0-3.0 | Balance stability and speed; buffering is annoying |
| **General browsing** | 1.0-1.5 | Speed matters more; slight jitter acceptable |
| **File downloads** | 0.5-1.0 | Speed is king; jitter barely matters |

### Default: 2.0 (Balanced)

The default weight of **2.0** means:
- 10ms of jitter = 20ms penalty
- Balanced between speed and stability
- Good for most use cases

## Usage Examples

### Gaming (Prioritize Stability)
```powershell
.\Test-DNSProviders.ps1 -SortByScore -JitterWeight 4.0
```
Heavy penalty for jitter → Selects most stable DNS even if slightly slower

### Streaming (Balanced)
```powershell
.\Test-DNSProviders.ps1 -SortByScore -JitterWeight 2.5
```
Moderate penalty for jitter → Good balance for Netflix, Twitch, YouTube

### Gaming + Streaming Tests
```powershell
.\Test-DNSProviders.ps1 -SortByScore -JitterWeight 3.0 -TestEDNS0 -TestTCP
```
Combines jitter-aware scoring with EDNS0 and TCP fallback tests

### Quick Gaming Test
```powershell
.\Test-DNSProviders.ps1 -QuickTest -SortByScore -JitterWeight 4.0 -TopResults 5
```
Fast test with heavy jitter penalty

### General Use (Traditional)
```powershell
.\Test-DNSProviders.ps1
```
Traditional sorting by response time only (no jitter penalty)

## Real-World Impact

### Example 1: Why Jitter Matters

**DNS A** (Traditional Winner):
- Response: 550ms
- Jitter: 80ms
- **Range: 470-630ms** ⚠️ Unpredictable!

**DNS B** (Jitter-Aware Winner):
- Response: 570ms
- Jitter: 2ms
- **Range: 568-572ms** ✓ Consistent!

For gaming, **DNS B** is far superior despite being 20ms slower on average.

### Example 2: Score Comparison

Using **JitterWeight = 2.5**:

```
DNS A: 550 + (80 × 2.5) = 750 score
DNS B: 570 + (2 × 2.5)  = 575 score  ✓ Winner
```

DNS B wins by 175 points!

## When to Use Each Method

### Use Traditional Sorting (No -SortByScore)
- ✓ General web browsing
- ✓ File downloads
- ✓ Basic DNS lookup speed tests
- ✓ When you want raw speed only

### Use Jitter-Aware Sorting (-SortByScore)
- ✓ Online gaming (CS2, Valorant, Fortnite)
- ✓ Video streaming (Netflix, Twitch, YouTube)
- ✓ VoIP calls (Discord, Teams, Zoom)
- ✓ Remote work (VPN, RDP)
- ✓ Real-time applications

## Parameters Summary

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-SortByScore` | Switch | Off | Enable composite score sorting |
| `-JitterWeight` | Double | 2.0 | Jitter multiplier (0.0-10.0) |
| `-TestEDNS0` | Switch | Off | Test EDNS0 support (CDN routing) |
| `-TestTCP` | Switch | Off | Test TCP fallback (gaming services) |

## Tips for Best Results

1. **Run multiple tests**: Jitter varies by time of day
   ```powershell
   .\Test-DNSProviders.ps1 -SortByScore -TestCount 10
   ```

2. **Test during peak hours**: When your network is most stressed
   ```powershell
   # Run at 8 PM on weekday
   .\Test-DNSProviders.ps1 -SortByScore -JitterWeight 3.0
   ```

3. **Combine with advanced tests**: Get complete picture
   ```powershell
   .\Test-DNSProviders.ps1 -SortByScore -TestEDNS0 -TestTCP
   ```

4. **Export results for comparison**: Track over time
   ```powershell
   .\Test-DNSProviders.ps1 -SortByScore -ExportPath ".\results"
   ```

## Score Interpretation

| Scenario | Traditional Rank | Score Rank | Why Score is Better |
|----------|------------------|------------|---------------------|
| Gaming DNS | May pick fastest | Picks most stable | Prevents lag spikes |
| Streaming | May pick fastest | Balances both | Reduces buffering |
| VoIP | May pick fastest | Prioritizes stability | Clearer calls |

## Conclusion

For **gaming and streaming**, always use:
```powershell
.\Test-DNSProviders.ps1 -SortByScore -JitterWeight 3.0 -TestEDNS0 -TestTCP
```

This ensures you get DNS servers that are:
- ✓ Consistently fast (low jitter)
- ✓ Support large UDP packets (EDNS0)
- ✓ Handle large responses properly (TCP)
- ✓ Optimized for real-time applications

Traditional sorting is misleading for gaming/streaming because it ignores consistency!
