# Windows DNS Configuration Script
# Run as Administrator

# Set DNS for all network adapters
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceAlias $_.Name -ServerAddresses ('149.112.112.10','9.9.9.11')
    Write-Host "Set DNS for $($_.Name) to 149.112.112.10, 9.9.9.11"
}

# Flush DNS cache
Clear-DnsClientCache
Write-Host "DNS cache cleared"
