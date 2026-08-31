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


if __name__ == "__main__":
    # 시연용 실행 코드
    print("--- Running Vulnerable Code Sample ---")
    login_user("admin' OR '1'='1", "1234")
    ping_server("127.0.0.1; echo 'Hacked'")