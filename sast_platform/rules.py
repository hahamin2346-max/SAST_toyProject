"""Single source of truth for the implemented detection rules.

Adding a new rule means: add one ``RuleSpec`` here and one detector in
``analyzers.py``. The analysis pipeline, persistence and API never change.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class RuleSpec:
    code: str
    kisa_num: int
    slug: str
    name: str
    category: str
    severity: str  # HIGH | MEDIUM | LOW
    languages: tuple[str, ...]
    confidence: float  # base confidence for the precise (Python AST) path
    message: str
    recommendation: str
    description: str
    reference: str


TEXT_BASELINE_CONFIDENCE = 0.5  # JavaScript / Java heuristic path

_INPUT = "입력 데이터 검증 및 표현"
_SEC = "보안 기능"
_ERR = "에러 처리"
_CODE = "코드 오류"
_CAPS = "캡슐화"
_ALL = ("PYTHON", "JAVASCRIPT", "JAVA")


RULE_SPECS: dict[str, RuleSpec] = {
    "KISA-INPUT-01": RuleSpec(
        "KISA-INPUT-01", 1, "01_sql_injection", "SQL 삽입", _INPUT, "HIGH", _ALL, 0.9,
        "사용자 입력이 SQL 문자열에 직접 결합되었습니다.",
        "파라미터 바인딩(플레이스홀더)을 사용해 입력을 데이터로만 처리하세요.",
        "검증되지 않은 입력이 동적 SQL 질의에 포함되면 SQL 삽입이 발생합니다.",
        "KISA SW보안약점 가이드 3.1 / CWE-89",
    ),
    "KISA-INPUT-02": RuleSpec(
        "KISA-INPUT-02", 2, "02_code_injection", "코드 삽입", _INPUT, "HIGH", _ALL, 0.9,
        "동적으로 전달된 문자열이 코드로 실행될 수 있습니다.",
        "eval/exec/Function 사용을 제거하고 명시적 분기 또는 안전한 파서를 사용하세요.",
        "eval, exec, new Function 등은 임의 코드 실행으로 이어질 수 있습니다.",
        "KISA SW보안약점 가이드 3.2 / CWE-94, CWE-95",
    ),
    "KISA-INPUT-03": RuleSpec(
        "KISA-INPUT-03", 3, "03_path_traversal", "경로 조작 및 자원 삽입", _INPUT, "HIGH", _ALL, 0.85,
        "사용자 입력이 파일 경로 생성에 사용되었습니다.",
        "파일명만 추출(basename)하고 기준 디렉터리를 벗어나지 않는지 검증하세요.",
        "상위 경로 이동 문자열(../)이 검증되지 않으면 임의 파일 접근이 가능합니다.",
        "KISA SW보안약점 가이드 3.3 / CWE-22, CWE-73",
    ),
    "KISA-INPUT-04": RuleSpec(
        "KISA-INPUT-04", 4, "04_xss", "크로스 사이트 스크립트", _INPUT, "MEDIUM", _ALL, 0.7,
        "검증되지 않은 입력이 HTML 응답으로 출력될 수 있습니다.",
        "출력 인코딩(이스케이프)을 적용하고 자동 이스케이프 템플릿을 사용하세요.",
        "입력을 HTML 컨텍스트에 그대로 출력하면 크로스 사이트 스크립트가 발생합니다.",
        "KISA SW보안약점 가이드 3.4 / CWE-79",
    ),
    "KISA-INPUT-05": RuleSpec(
        "KISA-INPUT-05", 5, "05_command_injection", "운영체제 명령어 삽입", _INPUT, "HIGH", _ALL, 0.9,
        "외부 명령 실행에 사용자 입력이 결합되었습니다.",
        "셸 실행을 피하고 인자를 리스트로 전달하며 화이트리스트 검증을 적용하세요.",
        "shell=True 또는 문자열 결합 명령은 운영체제 명령어 삽입으로 이어집니다.",
        "KISA SW보안약점 가이드 3.5 / CWE-78",
    ),
    "KISA-SEC-06": RuleSpec(
        "KISA-SEC-06", 23, "23_secret", "하드코딩된 중요정보", _SEC, "HIGH", _ALL, 0.8,
        "비밀번호·키 등 중요정보가 소스코드에 하드코딩되어 있습니다.",
        "환경변수나 비밀 관리 서비스에서 로드하고 저장소 이력에서 제거하세요.",
        "소스에 포함된 자격증명은 유출 시 즉시 악용될 수 있습니다.",
        "KISA SW보안약점 가이드 5.6 / CWE-798",
    ),
    "KISA-SEC-04": RuleSpec(
        "KISA-SEC-04", 21, "21_weak_crypto", "취약한 암호화 알고리즘 사용", _SEC, "HIGH", _ALL, 0.8,
        "취약하거나 더 이상 안전하지 않은 암호화·해시 알고리즘을 사용합니다.",
        "MD5·SHA-1·DES·RC4·ECB 대신 SHA-256 이상, AES-GCM 등 검증된 알고리즘을 사용하세요.",
        "MD5·SHA-1은 충돌 공격에, DES·RC4·ECB 모드는 복호화 공격에 취약합니다.",
        "KISA SW보안약점 가이드 5.4 / CWE-327, CWE-328",
    ),
    "KISA-SEC-08": RuleSpec(
        "KISA-SEC-08", 25, "25_weak_random", "적절하지 않은 난수값 사용", _SEC, "MEDIUM", _ALL, 0.7,
        "예측 가능한 난수 생성기를 보안 목적(토큰·키·비밀번호 등)에 사용합니다.",
        "secrets 모듈, os.urandom, java.security.SecureRandom 등 암호학적 난수 생성기를 사용하세요.",
        "random 모듈·Math.random·java.util.Random은 시드 예측이 가능해 보안 값 생성에 부적합합니다.",
        "KISA SW보안약점 가이드 5.8 / CWE-330, CWE-338",
    ),
    "KISA-SEC-11": RuleSpec(
        "KISA-SEC-11", 28, "28_secret_in_comment", "주석문 안에 포함된 시스템 주요정보", _SEC, "LOW", _ALL, TEXT_BASELINE_CONFIDENCE,
        "주석에 비밀번호·키 등 시스템 주요정보가 포함되어 있습니다.",
        "주석에서 자격증명·내부 URL·키를 제거하고 저장소 이력에서도 삭제하세요.",
        "주석에 남은 계정정보나 키는 소스 유출 시 그대로 악용됩니다.",
        "KISA SW보안약점 가이드 5.11 / CWE-615",
    ),
    "KISA-ERR-01": RuleSpec(
        "KISA-ERR-01", 36, "36_error_exposure", "오류 메시지 정보노출", _ERR, "MEDIUM", _ALL, 0.65,
        "예외 메시지·스택 트레이스가 사용자 응답으로 그대로 노출됩니다.",
        "사용자에게는 일반화된 메시지만 반환하고 상세 오류는 서버 로그에만 기록하세요.",
        "예외 내용을 응답에 포함하면 내부 경로·쿼리·구현 정보가 노출됩니다.",
        "KISA SW보안약점 가이드 4.1 / CWE-209, CWE-497",
    ),
    "KISA-CODE-05": RuleSpec(
        "KISA-CODE-05", 43, "43_unsafe_deserialization", "신뢰할 수 없는 데이터의 역직렬화", _CODE, "HIGH", _ALL, 0.8,
        "신뢰할 수 없는 데이터를 안전하지 않은 방식으로 역직렬화합니다.",
        "pickle·yaml.load(Loader 미지정)·ObjectInputStream 대신 JSON 등 안전한 포맷과 스키마 검증을 사용하세요.",
        "임의 객체를 복원하는 역직렬화는 원격 코드 실행으로 이어질 수 있습니다.",
        "KISA SW보안약점 가이드 6.5 / CWE-502",
    ),
    "KISA-CAPS-02": RuleSpec(
        "KISA-CAPS-02", 45, "45_debug_code", "제거되지 않고 남은 디버그 코드", _CAPS, "LOW", _ALL, 0.75,
        "배포 전 제거해야 할 디버그 코드가 남아 있습니다.",
        "breakpoint()·pdb·debugger 문과 debug=True 설정을 제거하고 로깅으로 대체하세요.",
        "디버그 코드는 내부 정보 노출이나 원격 코드 실행(예: 프레임워크 디버그 콘솔) 위험이 있습니다.",
        "KISA SW보안약점 가이드 7.2 / CWE-489",
    ),
}


def spec_for(code: str) -> RuleSpec | None:
    return RULE_SPECS.get(code)
