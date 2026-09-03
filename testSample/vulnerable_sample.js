// Vulnerable JavaScript sample for SAST baseline testing.
const cp = require('child_process');

function search(req, res) {
  // KISA-INPUT-01: SQL 삽입
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(query, (err, rows) => res.json(rows));

  // KISA-INPUT-04: 크로스 사이트 스크립트
  document.getElementById('out').innerHTML = req.query.name;

  // KISA-INPUT-02: 코드 삽입
  const result = eval(req.query.expr);

  // KISA-INPUT-03: 경로 조작
  fs.readFile('/data/' + req.query.file, 'utf8', (e, d) => res.send(d));

  // KISA-INPUT-05: 운영체제 명령어 삽입
  cp.exec('ping ' + req.query.host);

  return result;
}

// KISA-SEC-06: 하드코딩된 중요정보
const apiKey = "abcd1234efgh5678ijkl";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

const crypto = require('crypto');

// KISA-SEC-11: 주석문 안에 포함된 시스템 주요정보
// 배포용 관리자 password = Adm1n_Prod_Key 로 로그인 가능

function makeResetToken(user) {
  // KISA-SEC-08: 적절하지 않은 난수값 사용
  const token = Math.random().toString(36).slice(2);
  return token;
}

function digest(payload) {
  // KISA-SEC-04: 취약한 암호화 알고리즘 사용
  return crypto.createHash('md5').update(payload).digest('hex');
}

function handleError(req, res) {
  try {
    doWork(req);
  } catch (err) {
    // KISA-ERR-01: 오류 메시지 정보노출
    res.status(500).send('Internal error: ' + err.stack);
  }
  debugger; // KISA-CAPS-02: 제거되지 않고 남은 디버그 코드
}
