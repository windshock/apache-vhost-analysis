import a2conf
import sys
import socket
import os
import logging
import chardet  # 인코딩 자동 감지를 위해 chardet 사용
import tempfile  # 임시 파일 생성을 위한 라이브러리
import re

# ANSI escape codes for text color
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

# Alert 메시지 출력 함수
def print_alert(message, color="RED"):
    colors = {
        "RED": RED,
        "GREEN": GREEN,
        "YELLOW": YELLOW
    }
    print(f"{colors.get(color, RED)}{message}{RESET}")

# 공인 IP 대역과 사설 IP 대역을 구분하는 함수
def is_public_ip(ip):
    # 사설 IP 대역을 정의
    private_ip_ranges = [
        re.compile(r"^10\."),              # 10.0.0.0/8
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),  # 172.16.0.0/12
        re.compile(r"^192\.168\."),        # 192.168.0.0/16
    ]
    # IP가 사설 IP 대역에 속하지 않으면 공인 IP로 판단
    for private_range in private_ip_ranges:
        if private_range.match(ip):
            return False
    return True

# 로그 설정 (에러 로그를 stderr로 출력)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# 명령행 인자를 통해 파일 경로를 받음
if len(sys.argv) != 2:
    print("Usage: python script_name.py /path/to/vhost.conf_or_list")
    sys.exit(1)

input_file = sys.argv[1]

# vhost.conf 파일 경로인지, vhost 목록 파일 경로인지 확인하는 함수
def is_vhost_list(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        first_line = f.readline().strip()
        # 첫 번째 줄이 파일 경로처럼 보이면 목록 파일로 간주
        return os.path.exists(first_line)

# 인코딩 감지를 위한 함수
def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        return result['encoding']

# EUC-KR 파일을 UTF-8로 변환하는 함수
def convert_to_utf8(file_path, original_encoding):
    with open(file_path, 'r', encoding=original_encoding, errors='ignore') as f:
        content = f.read()
    return content.encode('utf-8').decode('utf-8')

# 주어진 vhost.conf 파일을 처리하는 함수
def process_vhost(vhost_conf_path):
    # vhost 파일 이름 추출
    vhost_file_name = os.path.basename(vhost_conf_path)

    # 세 번째 경로에서 hostname 추출 (슬래시로 구분하여 세 번째 요소 추출)
    try:
        raw_hostname = vhost_conf_path.split('/')[3]

        # hostname에 _가 있을 경우 처리 (hostname과 IP로 분리)
        if '_' in raw_hostname:
            hostname, ip = raw_hostname.split('_', 1)  # 1로 지정하여 두 번째 부분 전체를 IP로 받음
        else:
            hostname = raw_hostname
            ip = 'No IP'
    except ValueError as e:
        logging.error(f"Error parsing hostname and IP from path: {vhost_conf_path}. Error: {e}")
        return

    # vhost.conf 파일 경로에서 마지막 폴더를 제거하여 상위 경로로 이동
    httpd_conf_dir = os.path.dirname(os.path.dirname(vhost_conf_path))
    httpd_conf_path = os.path.join(httpd_conf_dir, 'httpd.conf')

    # httpd.conf에서 입력된 vhost 파일의 포함 여부 확인
    include_vhosts = 'No'
    try:
        if os.path.exists(httpd_conf_path):
            # httpd.conf 파일의 인코딩 감지
            encoding = detect_encoding(httpd_conf_path)
            if not encoding:
                encoding = 'utf-8'  # 감지가 실패할 경우 기본값으로 utf-8 사용

            # EUC-KR 인코딩일 경우 변환
            if encoding.lower() == 'euc-kr':
                httpd_conf_content = convert_to_utf8(httpd_conf_path, 'euc-kr')
            else:
                # 감지된 인코딩으로 httpd.conf 파일 읽기
                with open(httpd_conf_path, 'r', encoding=encoding, errors='ignore') as f:
                    httpd_conf_content = f.read()

            # UTF-8로 변환된 내용을 임시 파일에 저장
            with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as temp_file:
                temp_file.write(httpd_conf_content)
                temp_file_path = temp_file.name

            # a2conf에 변환된 임시 파일 경로 전달
            root_httpd = a2conf.Node(temp_file_path)

            # Include 지시문에서 정확히 argv로 받은 vhost 파일이 포함되었는지 확인
            for include_directive in root_httpd.children('Include'):
                included_file = os.path.basename(include_directive.args)
                if vhost_file_name == included_file:
                    include_vhosts = 'Yes'
                    break

    except Exception as e:
        logging.error(f"Error reading httpd.conf file: {httpd_conf_path}. Error: {e}")

    # 설정 파일 읽기
    try:
        root = a2conf.Node(vhost_conf_path)
    except Exception as e:
        logging.error(f"Error reading configuration file: {vhost_conf_path}. Error: {e}")
        return

    public_private_onefile = dict(ip_public='',ip_private='')
    # 모든 VirtualHost 블록 탐색
    for vhost in root.children('<VirtualHost>'):
        try:
            # ServerName 가져오기
            server_name = vhost.first('ServerName')
            if server_name:
                server_name = server_name.args
            else:
                server_name = 'No ServerName'

            # VirtualHost에서 포트 추출
            port = vhost.args.split(':')[-1] if ':' in vhost.args else 'No Port'

            # 포트가 포함된 ServerName에서 포트 제거
            if ':' in server_name:
                server_name = server_name.split(':')[0]

            # IP 주소 확인
            ip_address = 'No IP'
            ip_type = '-'
            if server_name != 'No ServerName' and server_name != '_default_':
                try:
                    ip_address = socket.gethostbyname(server_name)
                except socket.gaierror:
                    ip_address = 'Invalid domain'

            if ip_address != 'No IP' and ip_address != 'Invalid domain':
                ip_type = 'ip_public' if is_public_ip(ip_address) else 'ip_private'
                public_private_onefile[ip_type] = True
            elif server_name != '*' and server_name != '_default_' and include_vhosts == 'Yes':
                print_alert(f"!!ALERT!! This domain has no ip : {server_name}, {vhost_conf_path}")

            # CSV 형식으로 출력 (hostname과 ip를 각각 첫 번째와 두 번째 열에 추가, include 여부 추가)
            print(f"{hostname},{ip},{server_name},{port},{ip_address},{ip_type},{vhost_conf_path},{include_vhosts}")
        except Exception as e:
            logging.error(f"Error processing VirtualHost in file: {vhost_conf_path}. Error: {e}")
    if public_private_onefile["ip_public"] == True and public_private_onefile["ip_private"] == True:
        print_alert(f"!!ALERT!! Conf file has public and private domain : {vhost_conf_path}")

# 입력 파일이 목록 파일인 경우, 목록에 포함된 모든 vhost.conf 파일을 처리
if is_vhost_list(input_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        vhost_files = [line.strip() for line in f if line.strip()]
    for vhost_file in vhost_files:
        process_vhost(vhost_file)
else:
    # 단일 vhost.conf 파일일 경우 처리
    process_vhost(input_file)
