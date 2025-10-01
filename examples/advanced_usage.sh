#!/bin/bash

# IPDS Advanced Usage Examples
# This script demonstrates the advanced features of IPDS.

echo "=== IPDS Advanced Usage Examples ==="
echo

echo "1. Various Output Formats"
echo "================================"

echo "Output in JSON format:"
ipds 8.8.8.8 --format json
echo

echo "Output in YAML format:"
ipds 8.8.8.8 --format yaml
echo

echo "Output in CSV format:"
ipds 8.8.8.8 --format csv
echo

echo "2. Detailed Logging"
echo "================================"

echo "Run in verbose mode:"
ipds 8.8.8.8 --verbose
echo

echo "3. Various Geolocation Services"
echo "================================"

echo "Using IP-API service:"
ipds 8.8.8.8 --geo-service ipapi --geo-only
echo

echo "Using IPInfo service:"
ipds 8.8.8.8 --geo-service ipinfo --geo-only
echo

echo "4. Various ASN Services"
echo "================================"

echo "Using IP-API ASN service:"
ipds 8.8.8.8 --asn-service ipapi --asn-only
echo

echo "Using IPInfo ASN service:"
ipds 8.8.8.8 --asn-service ipinfo --asn-only
echo

echo "Using HackerTarget ASN service:"
ipds 8.8.8.8 --asn-service hackertarget --asn-only
echo

echo "5. Large-Scale Batch Processing"
echo "================================"

echo "Creating large IP list..."
cat > large_ip_list.txt << EOF
8.8.8.8
1.1.1.1
8.8.4.4
1.0.0.1
208.67.222.222
208.67.220.220
9.9.9.9
149.112.112.112
76.76.19.21
76.223.126.88
EOF

echo "Executing large-scale batch processing:"
ipds --file large_ip_list.txt --output large_batch_results.json
echo "Completed: large_batch_results.json"
echo

echo "6. Performance Testing"
echo "================================"

echo "Measuring single IP processing time:"
time ipds 8.8.8.8 --quiet
echo

echo "Measuring batch processing time:"
time ipds --file large_ip_list.txt --quiet --output performance_test.json
echo

echo "7. Error Handling Testing"
echo "================================"

echo "Testing invalid IP address:"
ipds 999.999.999.999 2>/dev/null || echo "Expected error: Invalid IP"
echo

echo "Testing non-existent file:"
ipds --file nonexistent.txt 2>/dev/null || echo "Expected error: File not found"
echo

echo "8. Result Analysis"
echo "================================"

if [ -f "large_batch_results.json" ]; then
    echo "Batch processing result analysis:"
    echo "Total IP count: $(jq length large_batch_results.json 2>/dev/null || echo 'Analysis unavailable')"
    echo "Private IP count: $(jq '[.[] | select(.basic_info.is_private == true)] | length' large_batch_results.json 2>/dev/null || echo 'Analysis unavailable')"
    echo "Public IP count: $(jq '[.[] | select(.basic_info.is_private == false)] | length' large_batch_results.json 2>/dev/null || echo 'Analysis unavailable')"
fi
echo

echo "9. Cleanup"
echo "================================"

echo "Generated files:"
ls -la *.txt *.json 2>/dev/null | head -10

echo
echo "Cleaning up temporary files..."
rm -f ip_list.txt large_ip_list.txt *.json 2>/dev/null
echo "Cleanup completed"
echo

echo "=== Advanced Usage Examples Complete ==="
