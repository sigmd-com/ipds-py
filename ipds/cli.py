"""
IPDS CLI
"""

import argparse
import json
import sys
from typing import List, Optional

from .core.ip_info import IPInfo
from .utils.validation import IPValidator


def main():
    """CLI entrypoint"""
    parser = argparse.ArgumentParser(
        description="IPDS - IP Describe Library",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ipds 8.8.8.8                    # Get all info of IP
  ipds 8.8.8.8 --asn-only         # Get only ASN info
  ipds 8.8.8.8 --geo-only         # Get only geolocation info
  ipds 8.8.8.8 --whois-only       # Get only WHOIS info
  ipds 8.8.8.8 --output result.json  # Save to JSON file
  ipds --file ip_list.txt         # Process multiple IPs
        """
    )
    
    parser.add_argument(
        "ip_address",
        nargs="?",
        help="IP address to analyze"
    )
    
    parser.add_argument(
        "--file", "-f",
        help="File containing list of IP addresses (one per line)"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="Output file to save results (JSON format)"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "yaml", "csv"],
        default="json",
        help="Output format (default: json)"
    )
    
    parser.add_argument(
        "--asn-only",
        action="store_true",
        help="Show only ASN information"
    )
    
    parser.add_argument(
        "--geo-only",
        action="store_true",
        help="Show only geolocation information"
    )
    
    parser.add_argument(
        "--whois-only",
        action="store_true",
        help="Show only WHOIS information"
    )
    
    parser.add_argument(
        "--basic-only",
        action="store_true",
        help="Show only basic IP information"
    )
    
    parser.add_argument(
        "--geo-service",
        choices=["ipapi", "ipinfo", "ipgeolocation"],
        default="ipapi",
        help="Geolocation service to use (default: ipapi)"
    )
    
    parser.add_argument(
        "--asn-service",
        choices=["ipapi", "ipinfo", "hackertarget"],
        default="ipapi",
        help="ASN service to use (default: ipapi)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet output (errors only)"
    )
    
    args = parser.parse_args()
    
    if not args.ip_address and not args.file:
        parser.error("Either IP address or file must be provided")
    
    if args.ip_address and args.file:
        parser.error("Cannot specify both IP address and file")
    
    if args.ip_address:
        process_single_ip(args)
    
    if args.file:
        process_file(args)


def process_single_ip(args):
    """Process a single IP address."""
    try:
        validator = IPValidator()
        if not validator.is_valid(args.ip_address):
            print(f"Error: Invalid IP address: {args.ip_address}", file=sys.stderr)
            sys.exit(1)
        
        ip_info = IPInfo(args.ip_address)
        
        if args.basic_only:
            result = ip_info.get_basic_info()
        elif args.asn_only:
            result = ip_info.get_asn_info()
        elif args.geo_only:
            result = ip_info.get_geolocation()
        elif args.whois_only:
            result = ip_info.get_whois_info()
        else:
            result = ip_info.get_all_info()
        
        output_result(result, args)
        
    except Exception as e:
        if not args.quiet:
            print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


def process_file(args):
    """Process a file containing IP addresses."""
    try:
        with open(args.file, 'r') as f:
            ip_addresses = [line.strip() for line in f if line.strip()]
        
        if not ip_addresses:
            print("Error: No IP addresses found in file", file=sys.stderr)
            sys.exit(1)
        
        results = []
        validator = IPValidator()
        
        for ip in ip_addresses:
            if not validator.is_valid(ip):
                if args.verbose:
                    print(f"Skipping invalid IP: {ip}", file=sys.stderr)
                continue
            
            try:
                ip_info = IPInfo(ip)
                
                if args.basic_only:
                    result = ip_info.get_basic_info()
                elif args.asn_only:
                    result = ip_info.get_asn_info()
                elif args.geo_only:
                    result = ip_info.get_geolocation()
                elif args.whois_only:
                    result = ip_info.get_whois_info()
                else:
                    result = ip_info.get_all_info()
                
                results.append(result)
                
            except Exception as e:
                if args.verbose:
                    print(f"Error processing {ip}: {str(e)}", file=sys.stderr)
                continue
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            if not args.quiet:
                print(f"Results saved to {args.output}")
        else:
            for result in results:
                print(json.dumps(result, indent=2))
                print()
        
    except FileNotFoundError:
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


def output_result(result, args):
    """Output result in specified format."""
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        if not args.quiet:
            print(f"Results saved to {args.output}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
