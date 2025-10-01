#!/bin/bash

# IPDS Basic IP Lookup Examples
# This script demonstrates the basic IP lookup functionality of IPDS.

echo "=== IPDS Basic IP Lookup Examples ==="
echo

echo "1. Single IP Address Lookup (8.8.8.8)"
echo "----------------------------------------"
ipds 8.8.8.8
echo

echo "2. Private IP Address Lookup (192.168.1.1)"
echo "----------------------------------------"
ipds 192.168.1.1
echo

echo "3. IPv6 Address Lookup (2001:db8::1)"
echo "----------------------------------------"
ipds 2001:db8::1
echo

echo "4. Basic Information Only (8.8.8.8)"
echo "----------------------------------------"
ipds 8.8.8.8 --basic-only
echo

echo "5. ASN Information Only (8.8.8.8)"
echo "----------------------------------------"
ipds 8.8.8.8 --asn-only
echo

echo "6. Geolocation Information Only (8.8.8.8)"
echo "----------------------------------------"
ipds 8.8.8.8 --geo-only
echo

echo "7. Network Information Only (8.8.8.8)"
echo "----------------------------------------"
ipds 8.8.8.8 --network-only
echo

echo "=== Examples Complete ==="
