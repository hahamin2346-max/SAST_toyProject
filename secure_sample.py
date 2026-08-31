import os
import sqlite3
import subprocess
import re
from pathlib import Path

# ==============================================================================
# Secure Code Sample for SAST Testing
# ==============================================================================

# [보안 조치 1] KISA-SEC-06 대응: 환경변수를 활용한 중요정보 관리
# 소스코드에 하드코딩하지 않고 외부 환경변수에서 로드
DATABASE_PASSWORD = os.getenv("DB_PASSWORD")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_KEY")


def login_user(username, password):
    """
    [보안 조치 2] KISA-INPUT-01 대응: 파라미터화된 쿼리 (PreparedStatement)
    플레이스홀더(?)를 사용하여 사용자 입력값을 데이터로만 처리
    """
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()

    # 안전한 쿼리 작성 방식
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    conn.close()
    return user


def ping_server(target_host):
    """
    [보안 조치 3] KISA-INPUT-05 대응: 입력값 화이트리스트 검증 & OS 셸 실행 차단
    1. 정규식으로 IP/도메인 포맷 검증
    2. subprocess.run()에 리스트 형태로 인자 전달 (shell=False)
    """
    # 1. 입력값 정규식 검증
    host_pattern = re.compile(r'^[a-zA-Z0-9.-]+$')
    if not host_pattern.match(target_host):
        raise ValueError("부적절한 형식의 호스트 입력값입니다.")

    # 2. 인자를 리스트로 전달하여 셸 메타문자 해석 차단
    command = ["ping", "-c", "1", target_host]
    
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return result.stdout


def read_user_file(file_name):
    """
    [보안 조치 4] KISA-INPUT-03 대응: 경로 검증 및 화이트리스트/Path 객체 이용
    파일 이름 추출 및 지정된 기본 디렉터리 벗어남 여부 검사
    """
    base_dir = Path("/var/www/uploads/").resolve()
    
    # 순수 파일명만 추출하여 경로 조작 문자열 제거
    safe_filename = os.path.basename(file_name)
    target_path = (base_dir / safe_filename).resolve()

    # 상위 디렉토리 참조 차단 검증
    if not str(target_path).startswith(str(base_dir)):
        raise PermissionError("허용되지 않은 파일 경로 접근입니다.")

    with open(target_path, 'r', encoding='utf-8') as f:
        return f.read()


def calculate_expression(a, b, operation):
    """
    [보안 조치 5] KISA-INPUT-02 대응: eval() 제거 및 안전한 연산 조건문 대체
    위험한 임의 코드 실행 함수를 제거하고 명시적인 사칙연산 로직만 허용
    """
    if operation == "add":
        return a + b
    elif operation == "subtract":
        return a - b
    elif operation == "multiply":
        return a * b
    elif operation == "divide":
        if b == 0:
            raise ValueError("0으로 나눌 수 없습니다.")
        return a / b
    else:
        raise ValueError("지원하지 않는 연산자입니다.")


if __name__ == "__main__":
    # 시연용 실행 코드
    print("--- Running Secure Code Sample ---")
    try:
        login_user("admin", "secure_password_123")
        ping_server("127.0.0.1")
    except Exception as e:
        print(f"Error: {e}")