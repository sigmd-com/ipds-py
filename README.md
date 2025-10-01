# IPDS - IP Data Service

A comprehensive Python library and CLI tool for IP address analysis, network information retrieval, and geolocation services.

## Features

- **IP Address Analysis** - Basic IP properties, validation, and classification
- **Network Information** - Subnet masks, CIDR notation, network ranges, and broadcast addresses
- **ASN Lookup** - Autonomous System Number lookup with organization details
- **Geolocation** - Country, region, city, ISP, and timezone information
- **WHOIS Data** - IP and domain WHOIS information
- **Batch Processing** - Analyze multiple IP addresses simultaneously
- **Multiple Output Formats** - JSON, YAML, and CSV export options
- **Network Scanning** - Scan network ranges and analyze security

## Installation

```bash
pip install ipds
```

## Quick Start

### Command Line Interface

```bash
# Basic IP lookup
ipds 8.8.8.8

# Network information only
ipds 8.8.8.8 --network-only

# ASN information only
ipds 8.8.8.8 --asn-only

# Geolocation only
ipds 8.8.8.8 --geo-only

# Batch processing from file
ipds --file ip_list.txt

# Save results to file
ipds 8.8.8.8 --output results.json
```

### Python API

```python
from ipds import IPInfo

# Create IPInfo object
ip_info = IPInfo("8.8.8.8")

# Get all information
all_info = ip_info.get_all_info()
print(all_info)

# Get specific information
basic_info = ip_info.get_basic_info()
network_info = ip_info.get_network_info()
asn_info = ip_info.get_asn_info()
geo_info = ip_info.get_geolocation_info()
whois_info = ip_info.get_whois_info()
```

## Examples

### Basic IP Analysis

```python
from ipds import IPInfo

ip_info = IPInfo("192.168.1.1")

# Basic properties
basic = ip_info.get_basic_info()
print(f"IP Version: IPv{basic['version']}")
print(f"Private IP: {basic['is_private']}")
print(f"Global IP: {basic['is_global']}")

# Network information
network = ip_info.get_network_info()
print(f"Network Range: {network['network_range']}")
print(f"Subnet Mask: {network['subnet_mask']}")
print(f"Broadcast: {network['broadcast_address']}")
```

### Public IP Analysis

```python
from ipds import IPInfo

ip_info = IPInfo("8.8.8.8")

# Get ASN information
asn_info = ip_info.get_asn_info()
print(f"ASN: {asn_info['asn']}")
print(f"Organization: {asn_info['asn_name']}")

# Get geolocation
geo_info = ip_info.get_geolocation_info()
print(f"Country: {geo_info['country']}")
print(f"City: {geo_info['city']}")
print(f"ISP: {geo_info['isp']}")
```

### Batch Processing

```python
from ipds import IPInfo

ip_addresses = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]

results = []
for ip in ip_addresses:
    ip_info = IPInfo(ip)
    result = {
        "ip_address": ip,
        "basic_info": ip_info.get_basic_info(),
        "network_info": ip_info.get_network_info()
    }
    results.append(result)

print(f"Processed {len(results)} IP addresses")
```

## CLI Options

```bash
ipds [IP_ADDRESS] [OPTIONS]

Options:
  --file FILE              Process IPs from file
  --output FILE            Save results to file
  --format FORMAT          Output format (json, yaml, csv)
  --basic-only             Show only basic IP information
  --network-only           Show only network information
  --asn-only               Show only ASN information
  --geo-only               Show only geolocation information
  --whois-only             Show only WHOIS information
  --geo-service SERVICE    Geolocation service (ipapi, ipinfo)
  --asn-service SERVICE    ASN service (ipapi, ipinfo, hackertarget)
  --verbose                Verbose output
  --quiet                  Quiet output
  --help                   Show help message
```

## Output Formats

### JSON (Default)
```json
{
  "ip_address": "8.8.8.8",
  "basic_info": {
    "version": 4,
    "is_private": false,
    "is_global": true,
    "is_multicast": false,
    "is_loopback": false,
    "is_link_local": false,
    "is_reserved": false
  },
  "network_info": {
    "network_address": "8.8.8.0",
    "subnet_mask": "255.255.255.0",
    "subnet_mask_cidr": "/24",
    "broadcast_address": "8.8.8.255",
    "total_addresses": 256,
    "usable_addresses": 254,
    "network_range": "8.8.8.0/24"
  },
  "asn_info": {
    "asn": "AS15169",
    "asn_name": "Google LLC",
    "isp": "Google LLC"
  },
  "geolocation": {
    "country": "United States",
    "country_code": "US",
    "region": "VA",
    "city": "Ashburn",
    "lat": 39.03,
    "lon": -77.5,
    "timezone": "America/New_York",
    "isp": "Google LLC"
  }
}
```

## Network Analysis

IPDS provides detailed network analysis including:

- **Subnet Mask Calculation** - Automatic subnet mask detection
- **CIDR Notation** - Network range in CIDR format
- **Broadcast Address** - Network broadcast address
- **Address Count** - Total and usable address counts
- **ASN Network Ranges** - For public IPs, finds the specific network range

### Private IP Networks

For private IPs, IPDS automatically detects the network class and provides:
- Class A (10.0.0.0/8)
- Class B (172.16.0.0/12) 
- Class C (192.168.0.0/16)

### Public IP Networks

For public IPs, IPDS:
1. Looks up the ASN (Autonomous System Number)
2. Retrieves all network prefixes announced by that ASN
3. Finds the specific network range containing the IP
4. Provides detailed subnet information

## Services Integration

IPDS integrates with multiple external services:

- **IP-API** - Primary geolocation and ASN service
- **IPInfo** - Alternative geolocation service
- **HackerTarget** - ASN lookup service
- **RIPE Stat** - ASN network prefix data
- **BGPView** - BGP routing information

## Error Handling

IPDS includes comprehensive error handling:
- Invalid IP address validation
- Network connectivity issues
- API service failures
- Graceful degradation when services are unavailable

## Requirements

- Python 3.7+
- Internet connection for external API calls
- Required packages: requests, ipaddress

## Examples Directory

The package includes example scripts in the `examples/` directory:

- `basic_ip_lookup.sh` - Basic IP lookup examples
- `network_analysis.sh` - Network analysis examples
- `batch_processing.sh` - Batch processing examples
- `advanced_usage.sh` - Advanced usage examples
- `python_api_example.py` - Python API examples
- `network_scanner.py` - Network scanning examples

## License

MIT License

## Support

For issues and questions, please open an issue on the GitHub repository.