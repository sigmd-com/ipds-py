#!/bin/bash

# IPDS 고급 사용 예제
# 이 스크립트는 IPDS의 고급 기능들을 보여줍니다.

echo "=== IPDS 고급 사용 예제 ==="
echo

echo "1. 다양한 출력 형식"
echo "================================"

echo "JSON 형식으로 출력:"
ipds 8.8.8.8 --format json
echo

echo "YAML 형식으로 출력:"
ipds 8.8.8.8 --format yaml
echo

echo "CSV 형식으로 출력:"
ipds 8.8.8.8 --format csv
echo

echo "2. 상세한 로깅"
echo "================================"

echo "Verbose 모드로 실행:"
ipds 8.8.8.8 --verbose
echo

echo "3. 다양한 지리적 위치 서비스"
echo "================================"

echo "IP-API 서비스 사용:"
ipds 8.8.8.8 --geo-service ipapi --geo-only
echo

echo "IPInfo 서비스 사용:"
ipds 8.8.8.8 --geo-service ipinfo --geo-only
echo

echo "4. 다양한 ASN 서비스"
echo "================================"

echo "IP-API ASN 서비스 사용:"
ipds 8.8.8.8 --asn-service ipapi --asn-only
echo

echo "IPInfo ASN 서비스 사용:"
ipds 8.8.8.8 --asn-service ipinfo --asn-only
echo

echo "HackerTarget ASN 서비스 사용:"
ipds 8.8.8.8 --asn-service hackertarget --asn-only
echo

echo "5. 대용량 배치 처리"
echo "================================"

echo "대용량 IP 목록 생성 중..."
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

echo "대용량 배치 처리 실행:"
ipds --file large_ip_list.txt --output large_batch_results.json
echo "완료: large_batch_results.json"
echo

echo "6. 성능 테스트"
echo "================================"

echo "단일 IP 처리 시간 측정:"
time ipds 8.8.8.8 --quiet
echo

echo "배치 처리 시간 측정:"
time ipds --file large_ip_list.txt --quiet --output performance_test.json
echo

echo "7. 에러 처리 테스트"
echo "================================"

echo "유효하지 않은 IP 주소 테스트:"
ipds 999.999.999.999 2>/dev/null || echo "예상된 오류: 유효하지 않은 IP"
echo

echo "존재하지 않는 파일 테스트:"
ipds --file nonexistent.txt 2>/dev/null || echo "예상된 오류: 파일을 찾을 수 없음"
echo

echo "8. 결과 분석"
echo "================================"

if [ -f "large_batch_results.json" ]; then
    echo "배치 처리 결과 분석:"
    echo "총 IP 개수: $(jq length large_batch_results.json 2>/dev/null || echo '분석 불가')"
    echo "프라이빗 IP 개수: $(jq '[.[] | select(.basic_info.is_private == true)] | length' large_batch_results.json 2>/dev/null || echo '분석 불가')"
    echo "공인 IP 개수: $(jq '[.[] | select(.basic_info.is_private == false)] | length' large_batch_results.json 2>/dev/null || echo '분석 불가')"
fi
echo

echo "9. 정리"
echo "================================"

echo "생성된 파일들:"
ls -la *.txt *.json 2>/dev/null | head -10

echo
echo "임시 파일 정리 중..."
rm -f ip_list.txt large_ip_list.txt *.json 2>/dev/null
echo "정리 완료"
echo

echo "=== 고급 사용 예제 완료 ==="
