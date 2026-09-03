import os
import sqlite3
import subprocess

# ==============================================================================
# Vulnerable Code Sample for SAST Testing
# ==============================================================================

# [취약점 1] KISA-SEC-06: 하드코딩된 중요정보 (Hardcoded Secret)
# 소스코드 내에 비밀번호나 API 키가 평문으로 포함되어 있음
DATABASE_PASSWORD = "AdminPassword123!@#"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def login_user(username, password):
    """
    [취약점 2] KISA-INPUT-01: SQL 삽입 (SQL Injection)
    사용자 입력값을 f-string으로 쿼리에 직접 결합하여 SQL Injection 발생
    """
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    # 입력값 검증 없이 쿼리 생성
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"[LOG] Executing query: {query}")
    
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user


def ping_server(target_host):
    """
    [취약점 3] KISA-INPUT-05: 운영체제 명령어 삽입 (Command Injection)
    os.system() 및 입력값 결합을 사용하여 OS 명령어 주입 가능
    """
    # target_host에 "127.0.0.1; cat /etc/passwd" 입력 시 악성 명령어 수행됨
    command = "ping -c 1 " + target_host
    print(f"[LOG] Running command: {command}")
    
    # 셸을 통해 직접 명령어를 실행
    os.system(command)


def read_user_file(file_name):
    """
    [취약점 4] KISA-INPUT-03: 경로 조작 및 자원 삽입 (Path Traversal)
    상위 디렉터리 이동 문자열('../')에 대한 검증이 없어 임의 파일 읽기 가능
    """
    base_dir = "/var/www/uploads/"
    # file_name에 "../../etc/passwd" 입력 시 상위 경로 파일 접근
    full_path = base_dir + file_name
    
    with open(full_path, 'r', encoding='utf-8') as f:
        return f.read()


def calculate_expression(user_input_expr):
    """
    [취약점 5] KISA-INPUT-02: 코드 삽입 / 위험한 함수 사용 (Code Injection / Eval)
    신뢰할 수 없는 사용자 입력값을 eval() 함수로 직접 실행
    """
    # user_input_expr에 "__import__('os').system('rm -rf /')" 등 입력 가능
    result = eval(user_input_expr)
    return result


import hashlib
import pickle
import random
import yaml

# [취약점 6] KISA-SEC-11: 주석문 안에 포함된 시스템 주요정보
# 운영 DB 접속: admin_password = P@ssw0rd_prod_2024 (임시)


def issue_session_token(user_id):
    """[취약점 7] KISA-SEC-08: 적절하지 않은 난수값 사용"""
    # 예측 가능한 random 모듈로 세션 토큰을 생성
    session_token = str(random.randint(100000, 999999))
    return session_token


def load_profile(blob):
    """[취약점 8] KISA-CODE-05: 신뢰할 수 없는 데이터의 역직렬화"""
    profile = pickle.loads(blob)
    config = yaml.load(blob)
    return profile, config


def fingerprint(raw):
    """[취약점 9] KISA-SEC-04: 취약한 암호화 알고리즘 사용"""
    return hashlib.md5(raw.encode()).hexdigest()


def start_server(app):
    """[취약점 10] KISA-CAPS-02: 제거되지 않고 남은 디버그 코드"""
    breakpoint()
    app.run(host="0.0.0.0", debug=True)


def handle_request(request):
    """[취약점 11] KISA-ERR-01: 오류 메시지 정보노출"""
    try:
        return process(request)
    except Exception as err:
        return HttpResponse(str(err))


if __name__ == "__main__":
    # 시연용 실행 코드
    print("--- Running Vulnerable Code Sample ---")
    login_user("admin' OR '1'='1", "1234")
    ping_server("127.0.0.1; echo 'Hacked'")