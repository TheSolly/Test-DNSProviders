#!/bin/bash
# Linux DNS Configuration Script
# Run with sudo

# Backup original resolv.conf
cp /etc/resolv.conf /etc/resolv.conf.backup

# Set new DNS servers
echo "nameserver 149.112.112.10" > /etc/resolv.conf
echo "nameserver 9.9.9.11" >> /etc/resolv.conf

# For systems using systemd-resolved
systemctl restart systemd-resolved 2>/dev/null || true

echo "DNS configuration updated"
echo "Primary: 149.112.112.10"
echo "Secondary: 9.9.9.11"
