import ast
from dataclasses import dataclass
from pathlib import Path
from .models import Rule


@dataclass
class RawFinding:
    rule_code: str
    line_number: int
    message: str
    evidence: str
    confidence: float = 0.95


class Analyzer:
    language = ""
    def analyze(self, source: str, file_path: str) -> list[RawFinding]:
        raise NotImplementedError


class PythonAnalyzer(Analyzer):
    language = "PYTHON"

    def analyze(self, source: str, file_path: str) -> list[RawFinding]:
        tree = ast.parse(source, filename=file_path)
        lines = source.splitlines()
        results: list[RawFinding] = []
        tainted_sql: set[str] = set()
        tainted_paths: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if isinstance(node.value, ast.JoinedStr):
                            tainted_sql.add(target.id)
                        tainted_paths.add(target.id)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
                results.append(RawFinding("KISA-INPUT-02", node.lineno, "사용자 입력이 eval을 통해 실행될 수 있습니다.", lines[node.lineno - 1].strip()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"system", "popen"}:
                results.append(RawFinding("KISA-INPUT-05", node.lineno, "셸을 통한 명령 실행이 탐지되었습니다.", lines[node.lineno - 1].strip()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute" and node.args:
                query = node.args[0]
                if isinstance(query, (ast.JoinedStr, ast.BinOp)) or (isinstance(query, ast.Name) and query.id in tainted_sql):
                    results.append(RawFinding("KISA-INPUT-01", node.lineno, "SQL 문에 입력값이 직접 결합될 수 있습니다.", lines[node.lineno - 1].strip()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.BinOp) or (isinstance(arg, ast.Name) and arg.id in tainted_paths):
                    results.append(RawFinding("KISA-INPUT-03", node.lineno, "검증되지 않은 경로 결합으로 경로 조작이 가능합니다.", lines[node.lineno - 1].strip()))
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                target = next((t.id for t in node.targets if isinstance(t, ast.Name)), "")
                if any(word in target.lower() for word in ("password", "secret", "api_key", "access_key")):
                    results.append(RawFinding("KISA-SEC-06", node.lineno, "중요정보가 소스코드에 하드코딩되어 있습니다.", lines[node.lineno - 1].strip()))
        return results


class AnalyzerRegistry:
    def __init__(self):
        self._analyzers = {PythonAnalyzer.language: PythonAnalyzer()}

    def register(self, language: str, analyzer: Analyzer) -> None:
        self._analyzers[language.upper()] = analyzer

    def get(self, language: str) -> Analyzer:
        try:
            return self._analyzers[language.upper()]
        except KeyError:
            raise ValueError(f"지원하지 않는 분석 언어입니다: {language}")
