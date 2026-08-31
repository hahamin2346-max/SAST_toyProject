# Deep Interview Context Snapshot

- Task statement: 프로젝트를 받아 정적 분석하고 보안 취약점을 탐지하는 SAST 프로그램을 만들고자 함.
- Desired outcome: `SASTdesign.pen`의 화면 흐름과 `상세 요구사항.txt`, `DB구성정보.txt`를 바탕으로 구현 가능한 제품 명세를 확정한 뒤 후속 설계·개발로 넘김.
- Stated solution: Java, JavaScript, Python 대상 구조화 분석 또는 동등한 방식, KISA 49개 진단 기준 카탈로그, 분석 결과 저장·조회 기능을 갖춘 시스템.
- Probable intent hypothesis: 배포 전 소스코드 취약점을 반복 가능하게 진단하고, 관리자/일반 사용자별 프로젝트와 결과 접근을 통제하는 내부용 웹 서비스 구축.
- Known facts/evidence: 요구사항 문서는 SFR 17개, DAR 10개, SEC 10개, TST 8개, QLT 5개를 정의함. DB 문서는 users, projects, project_members, rules, analysis_runs, findings 6개 테이블과 관계·인덱스를 정의함. 설계 파일에는 로그인·회원가입·대시보드·프로젝트 등록·KISA 가이드·진단 히스토리·취약점 상세·규칙/언어/사용자 권한 관리 화면이 있음. 샘플은 Python의 취약/보안 코드 비교용임.
- Constraints: 비밀번호 평문 금지, 인증·RBAC·프로젝트 소속 검증, 작업영역 격리·경로 검증, 분석 자원 제한, 결과 추적성과 재현성, 외부 구성요소 보안 관리가 요구됨.
- Unknowns/open questions: 첫 구현 단계의 범위와 우선순위, 배포 형태 및 기술 스택, 실제 분석 엔진 수준, 소스 입력 방식의 우선순위, 인증 방식, 운영·성능 목표, KISA 49개 항목의 구현 범위.
- Decision-boundary unknowns: MVP에 포함/제외할 화면·기능, 자동으로 결정 가능한 구현 세부사항과 사용자 확인이 필요한 아키텍처·보안 정책.
- Likely codebase touchpoints: 현재 애플리케이션 코드는 없으며 향후 백엔드/프론트엔드/분석 엔진/DB 마이그레이션/테스트가 생성 대상임.
- Relevant repo docs/rules/context inspected: 제공된 루트 `AGENTS.md` 지침, `상세 요구사항.txt`, `DB구성정보.txt`, `kisa보안가이드 정리.txt`, `SASTdesign.pen`, `secure_sample.py`, `vulnerable_sample.py`.
- Terminology or doc/code conflicts found: `DB구성정보.txt` 설명 중 `refere nce_info` 오탈자는 SQL 정의의 `reference_info`와 불일치함. 요구사항의 “구조화된 코드 분석 방식 또는 동등한 방식”은 구현 방식 선택을 열어둠. 설계의 “회원가입” 화면은 기능 요구사항에 명시되어 있지 않음.
- Prompt-safe initial-context summary status: recorded.
