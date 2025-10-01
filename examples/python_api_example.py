#!/usr/bin/env python3
"""
IPDS Python API 사용 예제
이 스크립트는 IPDS의 Python API를 사용하는 방법을 보여줍니다.
"""

import sys
import os
import json
from typing import List, Dict, Any

# IPDS 모듈 import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ipds.core.ip_info import IPInfo
from ipds.utils.validation import IPValidator


def basic_ip_analysis():
    """기본 IP 분석 예제"""
    print("=== 기본 IP 분석 예제 ===")
    
    ip_addresses = [
        "8.8.8.8",      # Google DNS
        "1.1.1.1",      # Cloudflare DNS
        "192.168.1.1",  # 프라이빗 IP
        "10.0.0.1",     # 프라이빗 IP
        "127.0.0.1",    # 루프백
        "180.66.201.68" # SK Broadband
    ]
    
    validator = IPValidator()
    
    for ip in ip_addresses:
        print(f"\n--- {ip} 분석 ---")
        
        try:
            # IP 유효성 검사
            if not validator.is_valid(ip):
                print(f"❌ 유효하지 않은 IP 주소: {ip}")
                continue
            
            # IPInfo 객체 생성
            ip_info = IPInfo(ip)
            
            # 기본 정보 조회
            basic_info = ip_info.get_basic_info()
            print(f"IP 버전: IPv{basic_info['version']}")
            print(f"프라이빗 IP: {basic_info['is_private']}")
            print(f"글로벌 IP: {basic_info['is_global']}")
            print(f"루프백 IP: {basic_info['is_loopback']}")
            
            # 네트워크 정보 조회
            network_info = ip_info.get_network_info()
            if 'network_range' in network_info:
                print(f"네트워크 범위: {network_info['network_range']}")
                print(f"서브넷 마스크: {network_info['subnet_mask']}")
                print(f"브로드캐스트: {network_info['broadcast_address']}")
            
        except Exception as e:
            print(f"❌ 오류 발생: {str(e)}")


def network_analysis():
    """네트워크 분석 예제"""
    print("\n=== 네트워크 분석 예제 ===")
    
    # 다양한 네트워크 유형의 IP들
    test_ips = {
        "Google DNS": "8.8.8.8",
        "Cloudflare DNS": "1.1.1.1",
        "SK Broadband": "180.66.201.68",
        "Class A Private": "10.0.0.1",
        "Class B Private": "172.16.0.1",
        "Class C Private": "192.168.1.1",
        "Loopback": "127.0.0.1",
        "Link Local": "169.254.1.1"
    }
    
    for name, ip in test_ips.items():
        print(f"\n--- {name} ({ip}) ---")
        
        try:
            ip_info = IPInfo(ip)
            network_info = ip_info.get_network_info()
            
            print(f"IP 타입: {network_info.get('ip_type', 'Unknown')}")
            print(f"프라이빗 IP: {network_info.get('is_private', 'Unknown')}")
            
            if 'network_range' in network_info:
                print(f"네트워크 범위: {network_info['network_range']}")
                print(f"서브넷 마스크: {network_info['subnet_mask']}")
                print(f"CIDR 표기법: {network_info['subnet_mask_cidr']}")
                print(f"총 주소 수: {network_info['total_addresses']}")
                print(f"사용 가능한 주소: {network_info['usable_addresses']}")
            
            if 'asn' in network_info:
                print(f"ASN: {network_info['asn']}")
                print(f"ASN 이름: {network_info.get('asn_name', 'Unknown')}")
            
        except Exception as e:
            print(f"❌ 오류 발생: {str(e)}")


def batch_processing():
    """배치 처리 예제"""
    print("\n=== 배치 처리 예제 ===")
    
    # IP 목록
    ip_list = [
        "8.8.8.8",
        "1.1.1.1", 
        "192.168.1.1",
        "10.0.0.1",
        "180.66.201.68"
    ]
    
    results = []
    
    print(f"총 {len(ip_list)}개의 IP 주소를 처리 중...")
    
    for i, ip in enumerate(ip_list, 1):
        print(f"처리 중... ({i}/{len(ip_list)}) {ip}")
        
        try:
            ip_info = IPInfo(ip)
            
            # 필요한 정보만 조회 (성능 최적화)
            result = {
                "ip_address": ip,
                "basic_info": ip_info.get_basic_info(),
                "network_info": ip_info.get_network_info()
            }
            
            results.append(result)
            
        except Exception as e:
            print(f"❌ {ip} 처리 중 오류: {str(e)}")
            results.append({
                "ip_address": ip,
                "error": str(e)
            })
    
    # 결과를 JSON 파일로 저장
    output_file = "batch_processing_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 배치 처리 완료! 결과가 {output_file}에 저장되었습니다.")
    
    # 간단한 통계 출력
    private_count = sum(1 for r in results if r.get('basic_info', {}).get('is_private', False))
    public_count = len(results) - private_count
    
    print(f"\n📊 통계:")
    print(f"  - 총 처리된 IP: {len(results)}")
    print(f"  - 프라이빗 IP: {private_count}")
    print(f"  - 공인 IP: {public_count}")


def custom_analysis():
    """사용자 정의 분석 예제"""
    print("\n=== 사용자 정의 분석 예제 ===")
    
    def analyze_ip_security(ip: str) -> Dict[str, Any]:
        """IP 보안 분석"""
        try:
            ip_info = IPInfo(ip)
            basic_info = ip_info.get_basic_info()
            network_info = ip_info.get_network_info()
            
            security_analysis = {
                "ip_address": ip,
                "is_private": basic_info["is_private"],
                "is_global": basic_info["is_global"],
                "is_loopback": basic_info["is_loopback"],
                "is_multicast": basic_info["is_multicast"],
                "is_reserved": basic_info["is_reserved"],
                "security_level": "unknown"
            }
            
            # 보안 레벨 결정
            if basic_info["is_private"]:
                security_analysis["security_level"] = "private"
            elif basic_info["is_loopback"]:
                security_analysis["security_level"] = "loopback"
            elif basic_info["is_multicast"]:
                security_analysis["security_level"] = "multicast"
            elif basic_info["is_reserved"]:
                security_analysis["security_level"] = "reserved"
            else:
                security_analysis["security_level"] = "public"
            
            # 네트워크 정보 추가
            if 'network_range' in network_info:
                security_analysis["network_range"] = network_info["network_range"]
                security_analysis["subnet_size"] = network_info["total_addresses"]
            
            return security_analysis
            
        except Exception as e:
            return {
                "ip_address": ip,
                "error": str(e),
                "security_level": "error"
            }
    
    # 테스트 IP들
    test_ips = ["8.8.8.8", "192.168.1.1", "127.0.0.1", "224.0.0.1", "0.0.0.0"]
    
    print("IP 보안 분석 결과:")
    for ip in test_ips:
        analysis = analyze_ip_security(ip)
        print(f"\n{ip}:")
        print(f"  보안 레벨: {analysis['security_level']}")
        print(f"  프라이빗: {analysis.get('is_private', 'N/A')}")
        print(f"  글로벌: {analysis.get('is_global', 'N/A')}")
        if 'network_range' in analysis:
            print(f"  네트워크: {analysis['network_range']}")


def main():
    """메인 함수"""
    print("🚀 IPDS Python API 사용 예제")
    print("=" * 50)
    
    try:
        # 기본 IP 분석
        basic_ip_analysis()
        
        # 네트워크 분석
        network_analysis()
        
        # 배치 처리
        batch_processing()
        
        # 사용자 정의 분석
        custom_analysis()
        
        print("\n✅ 모든 예제가 성공적으로 완료되었습니다!")
        
    except KeyboardInterrupt:
        print("\n\n⏹️  사용자에 의해 중단되었습니다.")
    except Exception as e:
        print(f"\n❌ 예상치 못한 오류가 발생했습니다: {str(e)}")


if __name__ == "__main__":
    main()
