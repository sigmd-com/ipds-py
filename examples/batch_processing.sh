#!/bin/bash

# IPDS 배치 처리 예제
# 이 스크립트는 IPDS의 배치 처리 기능을 보여줍니다.

echo "=== IPDS 배치 처리 예제 ==="
echo

echo "1. IP 목록 파일 생성"
echo "================================"

cat > ip_list.txt << EOF
8.8.8.8
1.1.1.1
192.168.1.1
10.0.0.1
172.16.0.1
127.0.0.1
180.66.201.68
EOF

echo "ip_list.txt 파일이 생성되었습니다:"
cat ip_list.txt
echo

echo "2. 배치 처리 실행"
echo "================================"

echo "모든 IP에 대한 전체 정보 조회:"
ipds --file ip_list.txt
echo

echo "3. 특정 정보만 배치 처리"
echo "================================"

echo "네트워크 정보만 조회:"
ipds --file ip_list.txt --network-only
echo

echo "ASN 정보만 조회:"
ipds --file ip_list.txt --asn-only
echo

echo "4. 결과를 파일로 저장"
echo "================================"

echo "배치 처리 결과를 batch_results.json에 저장 중..."
ipds --file ip_list.txt --output batch_results.json
echo "저장 완료: batch_results.json"
echo

echo "네트워크 정보만 batch_network.json에 저장 중..."
ipds --file ip_list.txt --network-only --output batch_network.json
echo "저장 완료: batch_network.json"
echo

echo "5. 정리"
echo "================================"

echo "생성된 파일들:"
ls -la *.txt *.json 2>/dev/null || echo "파일이 없습니다."
echo

echo "=== 배치 처리 예제 완료 ==="
