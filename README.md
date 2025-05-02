# DNS Benchmark

A powerful PowerShell script for benchmarking DNS providers and finding the fastest and most reliable DNS servers.

## Features

- Tests multiple DNS providers including Egyptian, Global, and Control D DNS servers
- Measures response time, jitter, and reliability
- Tests multiple DNS record types (A, AAAA, MX, TXT, NS)
- Supports parallel and sequential testing modes
- Provides detailed statistics and recommendations
- Generates configuration commands for Windows, Linux, and macOS

## Usage

`powershell
# Basic usage
.\Test-DNSProviders.ps1

# Test specific DNS categories
.\Test-DNSProviders.ps1 -Category Global     # Only test global DNS providers
.\Test-DNSProviders.ps1 -Category Egyptian   # Only test Egyptian DNS providers
.\Test-DNSProviders.ps1 -Category ControlD   # Only test Control D DNS providers

# Test with different parameters
.\Test-DNSProviders.ps1 -Parallel -MultiRecordTest -TestCount 10 -Timeout 5

# Export results to CSV
.\Test-DNSProviders.ps1 -ExportPath "C:\Temp\dns_results.csv"
`

## Requirements

- Windows PowerShell 5.1 or later
- DnsClient module
- Internet connectivity

## License

MIT
