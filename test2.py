from flask import Flask, request
import sqlite3
import os
import hashlib
import random
import pickle
import yaml

app = Flask(__name__)

# KISA-SEC-06 하드코딩된 중요정보
DB_PASSWORD = "admin1234"
API_KEY = "SECRET_API_KEY_123456"

# KISA-SEC-11 주석 내 시스템 정보
# DB Server: 192.168.0.10
# Admin Account: administrator

@app.route("/login")
def login():

    username = request.args.get("username")
    password = request.args.get("password")

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    # KISA-INPUT-01 SQL Injection
    query = (
        f"SELECT * FROM users "
        f"WHERE username='{username}' "
        f"AND password='{password}'"
    )

    cur.execute(query)

    return "Login Success"


@app.route("/calc")
def calc():

    expr = request.args.get("expr")

    # KISA-INPUT-02 Code Injection
    result = eval(expr)

    return str(result)


@app.route("/search")
def search():

    keyword = request.args.get("q")

    # KISA-INPUT-04 XSS
    return f"""
    <html>
        <body>
            검색어 : {keyword}
        </body>
    </html>
    """


@app.route("/ping")
def ping():

    host = request.args.get("host")

    # KISA-INPUT-05 OS Command Injection
    output = os.popen(f"ping -c 1 {host}").read()

    return output


@app.route("/hash")
def hash_pw():

    pw = request.args.get("pw")

    # KISA-SEC-04 취약한 암호화 알고리즘
    # KISA-SEC-12 솔트 없는 해시
    digest = hashlib.md5(pw.encode()).hexdigest()

    return digest


@app.route("/token")
def token():

    # KISA-SEC-08 부적절한 난수
    token = str(random.randint(100000, 999999))

    return token


@app.route("/load")
def load():

    data = request.args.get("data").encode()

    # KISA-CODE-05 신뢰불가 역직렬화
    obj = pickle.loads(data)

    return str(obj)


@app.route("/yaml")
def yaml_load():

    text = request.args.get("yaml")

    # KISA-CODE-05 신뢰불가 역직렬화
    obj = yaml.load(text, Loader=yaml.Loader)

    return str(obj)


@app.route("/error")
def error():

    try:
        1 / 0

    except Exception as e:

        # KISA-ERR-01 오류 메시지 정보 노출
        return f"""
        Error: {e}<br>
        Current Path: {os.getcwd()}<br>
        DB Password: {DB_PASSWORD}
        """


if __name__ == "__main__":

    # KISA-CAPS-02 남은 디버그 코드
    app.run(debug=True)