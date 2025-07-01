#!/bin/bash
# macOS DNS Configuration Script

# Get list of network services
services=$(networksetup -listallnetworkservices | grep -v "An asterisk")

# Set DNS for each network service
while IFS= read -r service; do
    if [[ "$service" != *"*"* ]]; then
        networksetup -setdnsservers "$service" 149.112.112.10 9.9.9.11
        echo "Set DNS for $service to 149.112.112.10, 9.9.9.11"
    fi
done <<< "$services"

# Flush DNS cache
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

echo "DNS configuration updated and cache flushed"
