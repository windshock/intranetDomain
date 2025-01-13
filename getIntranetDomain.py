import subprocess
import re

# 서브도메인 수집 및 DNS 질의
subfinder_result = subprocess.run(["subfinder", "-d", "skplanet.com"], capture_output=True, text=True)
domains = subfinder_result.stdout.splitlines()

# 내부 IP 대역 필터링
private_ip_pattern = re.compile(r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})$")

internal_ips = []
for domain in domains:
    dns_result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
    for line in dns_result.stdout.splitlines():
        if "Address" in line:
            ip = line.split()[-1]
            if private_ip_pattern.match(ip):
                internal_ips.append((domain, ip))

# 결과 출력
for domain, ip in internal_ips:
    print(f"{domain}: {ip}")
