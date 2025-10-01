#!/bin/bash

# IPDS 네트워크 분석 예제
# 이 스크립트는 IPDS의 네트워크 분석 기능을 보여줍니다.

echo "=== IPDS 네트워크 분석 예제 ==="
echo

echo "1. 프라이빗 IP 네트워크 분석"
echo "================================"

echo "Class A 프라이빗 IP (10.0.0.1):"
ipds 10.0.0.1 --network-only
echo

echo "Class B 프라이빗 IP (172.16.0.1):"
ipds 172.16.0.1 --network-only
echo

echo "Class C 프라이빗 IP (192.168.1.1):"
ipds 192.168.1.1 --network-only
echo

echo "2. 공인 IP 네트워크 분석"
echo "================================"

echo "Google DNS (8.8.8.8):"
ipds 8.8.8.8 --network-only
echo

echo "Cloudflare DNS (1.1.1.1):"
ipds 1.1.1.1 --network-only
echo

echo "SK Broadband (180.66.201.68):"
ipds 180.66.201.68 --network-only
echo

echo "3. 특수 IP 주소 분석"
echo "================================"

echo "루프백 주소 (127.0.0.1):"
ipds 127.0.0.1 --network-only
echo

echo "링크 로컬 주소 (169.254.1.1):"
ipds 169.254.1.1 --network-only
echo

echo "멀티캐스트 주소 (224.0.0.1):"
ipds 224.0.0.1 --network-only
echo

echo "4. 결과를 JSON 파일로 저장"
echo "================================"

echo "네트워크 분석 결과를 network_analysis.json에 저장 중..."
ipds 8.8.8.8 --output network_analysis.json
echo "저장 완료: network_analysis.json"
echo

echo "=== 네트워크 분석 예제 완료 ==="
