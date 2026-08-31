# Design

## Source of truth
- Status: Active
- Last refreshed: 2026-08-31
- Primary product surfaces: 로그인, 대시보드, 프로젝트, 진단 결과, KISA 규칙
- Evidence reviewed: `SASTdesign.pen`, `상세 요구사항.txt`, `DB구성정보.txt`

## Brand
- Personality: 신뢰감 있고 차분한 보안 도구
- Trust signals: 상태 배지, 분석 이력, 심각도 요약, 명확한 오류 메시지
- Avoid: 과도한 장식, 위험 상태를 색상만으로 표현하는 UI

## Product goals
- Goals: 프로젝트 보안 상태를 빠르게 확인하고 분석 결과를 조치로 연결
- Non-goals: UI에서 진단 규칙을 직접 작성하거나 DB 정책을 우회하는 것
- Success signals: 로그인 후 프로젝트와 최신 진단 상태를 한 화면에서 확인

## Personas and jobs
- Primary personas: 시스템 관리자, 프로젝트 일반 사용자
- User jobs: 프로젝트 등록, 분석 실행, 결과 필터링 및 상세 확인
- Key contexts of use: 내부 개발·보안 검토 데스크톱 환경

## Information architecture
- Primary navigation: 대시보드, 프로젝트, 진단 결과, KISA 규칙, 설정
- Core routes/screens: 로그인, 대시보드, 프로젝트 상세, 분석 결과
- Content hierarchy: 프로젝트 상태 → 심각도 요약 → 최근 분석 → 개별 Finding

## Design principles
- Principle 1: 위험도와 다음 행동을 먼저 보여준다.
- Principle 2: 서버 권한과 화면 권한을 동일하게 취급한다.
- Tradeoffs: MVP에서는 단일 페이지 화면으로 이동 비용을 줄이고, 세부 라우팅은 후속 단계로 둔다.

## Visual language
- Color: `#0B1220` 네이비, `#111C33` 패널, `#2563EB` 액션 블루, `#38BDF8` 포인트, `#F7F9FC` 배경
- Typography: Inter 우선, 시스템 산세리프 fallback
- Spacing/layout rhythm: 8px 배수, 데스크톱 중심 1200px 콘텐츠 폭
- Shape/radius/elevation: 8px 카드, 얕은 테두리와 그림자
- Motion: 짧은 로딩 상태만 사용
- Imagery/iconography: 텍스트 아이콘과 CSS 도형, 외부 이미지 없음

## Components
- Existing components to reuse: 없음
- New/changed components: Sidebar, StatCard, ProjectCard, FindingTable, LoginPanel
- Variants and states: loading, empty, error, severity high/medium/low
- Token/component ownership: `web/styles.css`

## Accessibility
- Target standard: WCAG 2.1 AA 지향
- Keyboard/focus behavior: native form controls와 visible focus
- Contrast/readability: 상태를 색상과 텍스트로 함께 표시
- Screen-reader semantics: label, button, table semantics 사용
- Reduced motion and sensory considerations: 필수 애니메이션 없음

## Responsive behavior
- Supported breakpoints/devices: 900px 이상 데스크톱, 640px 이상 태블릿/소형 화면
- Layout adaptations: 사이드바 축소, 카드 1열, 표 가로 스크롤
- Touch/hover differences: 버튼 최소 터치 영역 44px

## Interaction states
- Loading: 버튼과 섹션에 로딩 문구 표시
- Empty: 프로젝트/결과가 없다는 설명과 다음 행동 표시
- Error: API 오류를 상단 알림으로 표시
- Success: 로그인·프로젝트 생성·분석 요청 성공 알림
- Disabled: 처리 중인 분석 버튼 비활성화
- Offline/slow network, if applicable: 요청 실패 문구 표시

## Content voice
- Tone: 간결하고 전문적인 한국어
- Terminology: 프로젝트, 분석 실행, 진단 결과, 심각도, 규칙
- Microcopy rules: 기술 오류는 사용자가 다음 행동을 알 수 있게 작성

## Implementation constraints
- Framework/styling system: Python 표준 라이브러리 서버 + vanilla HTML/CSS/JS
- Design-token constraints: 기존 pen 색상과 간격 체계 유지
- Performance constraints: 외부 CDN과 런타임 의존성 없음
- Compatibility constraints: 최신 Chromium/Firefox/Safari
- Test/screenshot expectations: API 단위 테스트와 브라우저 수동 smoke test

## Open questions
- [ ] 실제 DB 연결 시 세션/토큰 저장 정책 / 운영 담당
- [ ] ZIP 업로드 및 분석 작업 큐의 운영 제한 / 인프라 담당
