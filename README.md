# SAST 플랫폼 토대

요구사항 문서를 기준으로 만든 실행 가능한 Python 표준 라이브러리 기반 골격입니다.

## 실행

```bash
python app.py
```

기본 계정은 데모용 `admin / change-me`이며 운영 환경에서는 반드시 교체해야 합니다.

## 범위

- 인증: PBKDF2 비밀번호 해시, 만료형 HMAC Bearer 토큰
- 권한: `ADMIN`, `USER`, 프로젝트 멤버십 기반 접근 제어
- 프로젝트/분석 실행/진단 결과 도메인 모델과 메모리 저장소
- KISA 49개 카탈로그 로딩
- Python AST 기반 분석기와 공통 결과 모델
- JSON HTTP API (`/health`, `/api/auth/login`, `/api/projects`, `/api/analysis`)

DB 연결은 의도적으로 포함하지 않았습니다. 저장소 인터페이스를 구현한 `InMemory*Repository`를 DB 어댑터로 교체하면 됩니다.

## 미구현/보류

- 실제 관계형 DB, 마이그레이션, 영속 트랜잭션
- 파일 업로드/Git 수집 및 격리된 작업 영역
- Java/JavaScript 파서와 진단 규칙
- 비동기 작업 큐, 자원 제한, 운영 배포 설정
