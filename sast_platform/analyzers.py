import ast
import re
from dataclasses import dataclass

from .rules import RULE_SPECS, TEXT_BASELINE_CONFIDENCE


@dataclass
class RawFinding:
    rule_code: str
    line_number: int
    message: str
    evidence: str
    confidence: float = 0.95
    column: int = 0  # 1-based; AST: col_offset + 1, regex: match.start() + 1


class Analyzer:
    language = ""

    def analyze(self, source: str, file_path: str) -> list[RawFinding]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Python — precise AST detectors
# ---------------------------------------------------------------------------

PY_DETECTORS: list = []


def python_detector(fn):
    """Register a generator ``fn(ctx) -> Iterable[RawFinding]``."""
    PY_DETECTORS.append(fn)
    return fn


class PyContext:
    def __init__(self, source: str, tree: ast.Module):
        self.source = source
        self.lines = source.splitlines()
        self.tree = tree
        self.string_built: set[str] = set()
        self.seq_names: set[str] = set()
        self._scan_assignments()

    def _is_str_expr(self, value: ast.AST) -> bool:
        if isinstance(value, ast.JoinedStr):
            return True
        if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.Mod)):
            # '+' / '%' that involves any name or string literal is treated as
            # string building (conservative: numeric-only expressions are ignored).
            for side in ast.walk(value):
                if isinstance(side, (ast.JoinedStr, ast.Name)):
                    return True
                if isinstance(side, ast.Constant) and isinstance(side.value, str):
                    return True
            return False
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr in {"format", "join"}:
            return True
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "str":
            return True
        if isinstance(value, ast.Name):
            return value.id in self.string_built
        return False

    def _scan_assignments(self) -> None:
        assigns = [n for n in ast.walk(self.tree) if isinstance(n, (ast.Assign, ast.AnnAssign))]
        for _ in range(3):
            changed = False
            for node in assigns:
                if node.value is None:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if self._is_str_expr(node.value):
                    for name in names:
                        if name not in self.string_built:
                            self.string_built.add(name)
                            changed = True
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    self.seq_names.update(names)
            if not changed:
                break

    def dynamic_string(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        if isinstance(node, ast.Name):
            return node.id in self.string_built
        return False

    def raw(self, code: str, node: ast.AST, message: str | None = None, confidence: float | None = None) -> RawFinding:
        spec = RULE_SPECS[code]
        line = getattr(node, "lineno", 1)
        evidence = self.lines[line - 1].strip() if 0 <= line - 1 < len(self.lines) else ""
        return RawFinding(
            code,
            line,
            message or spec.message,
            evidence,
            spec.confidence if confidence is None else confidence,
            getattr(node, "col_offset", 0) + 1,
        )


def _attr_owner(func: ast.AST) -> str:
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return func.value.id
        if isinstance(func.value, ast.Attribute):
            return func.value.attr
    return ""


def _kw_true(call: ast.Call, name: str) -> bool:
    kw = next((k for k in call.keywords if k.arg == name), None)
    return bool(kw and isinstance(kw.value, ast.Constant) and kw.value.value is True)


def _name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


_SQL_SINKS = {"execute", "executemany", "executescript", "raw", "mogrify"}


@python_detector
def _detect_sql_injection(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in _SQL_SINKS or not node.args:
            continue
        if len(node.args) >= 2:  # parameter binding -> data kept separate from query
            continue
        if ctx.dynamic_string(node.args[0]):
            yield ctx.raw("KISA-INPUT-01", node)


@python_detector
def _detect_code_injection(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            arg = node.args[0] if node.args else None
            confidence = 0.5 if isinstance(arg, ast.Constant) else None
            yield ctx.raw("KISA-INPUT-02", node, confidence=confidence)


_PATH_NAME_SINKS = {"open"}
_PATH_ATTR_SINKS = {
    "open", "remove", "unlink", "rename", "replace", "copy", "copyfile",
    "move", "rmtree", "send_file", "send_from_directory",
}
_PATH_SAFE_CALLS = {"basename", "resolve", "name", "stem", "secure_filename"}


def _literal_has_dotdot(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and ".." in node.value


@python_detector
def _detect_path_traversal(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        args: list[ast.AST] = []
        if isinstance(node.func, ast.Name) and node.func.id in _PATH_NAME_SINKS and node.args:
            args = [node.args[0]]
        elif isinstance(node.func, ast.Attribute) and node.func.attr in _PATH_ATTR_SINKS and node.args:
            args = [node.args[0]]
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "join" and _attr_owner(node.func) in {"path", "os"}:
            args = list(node.args)
        else:
            continue
        if any(
            isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr in _PATH_SAFE_CALLS
            for a in args
        ):
            continue
        if any(ctx.dynamic_string(a) or _literal_has_dotdot(a) for a in args):
            yield ctx.raw("KISA-INPUT-03", node)


_XSS_NAME_SINKS = {"render_template_string", "mark_safe", "Markup"}
_XSS_RESPONSE_SINKS = {"HttpResponse", "Response"}


@python_detector
def _detect_xss(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in _XSS_NAME_SINKS:
            yield ctx.raw("KISA-INPUT-04", node)
        elif isinstance(node.func, ast.Name) and node.func.id in _XSS_RESPONSE_SINKS and node.args and ctx.dynamic_string(node.args[0]):
            yield ctx.raw("KISA-INPUT-04", node, confidence=0.55)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "write" and node.args and ctx.dynamic_string(node.args[0]):
            yield ctx.raw("KISA-INPUT-04", node, confidence=0.5)


_SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen"}


@python_detector
def _detect_command_injection(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        owner, attr = _attr_owner(node.func), node.func.attr
        if attr in {"system", "popen"} and owner in {"os", ""}:
            yield ctx.raw("KISA-INPUT-05", node)
            continue
        if owner == "subprocess" and attr in _SUBPROCESS_CALLS:
            if _kw_true(node, "shell"):
                yield ctx.raw("KISA-INPUT-05", node)
                continue
            first = node.args[0] if node.args else None
            if first is None or isinstance(first, (ast.List, ast.Tuple)):
                continue
            if isinstance(first, ast.Name) and first.id in ctx.seq_names:
                continue
            if ctx.dynamic_string(first):
                yield ctx.raw("KISA-INPUT-05", node)


_SECRET_NAME = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|"
    r"token|credential|private[_-]?key|auth)",
    re.I,
)
_SECRET_PLACEHOLDER = re.compile(r"^(changeme|change-me|x+|your[_-].*|<.*>|\.\.\.|none|null|example.*)$", re.I)


@python_detector
def _detect_hardcoded_secret(ctx: PyContext):
    def emit(name: str, value: ast.AST, node: ast.AST):
        if not name or not _SECRET_NAME.search(name):
            return None
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            return None
        text = value.value
        if len(text) < 4 or _SECRET_PLACEHOLDER.match(text):
            return None
        return ctx.raw("KISA-SEC-06", node)

    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found = emit(target.id, node.value, node)
                    if found:
                        yield found
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            found = emit(node.target.id, node.value, node)
            if found:
                yield found
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg:
                    found = emit(kw.arg, kw.value, kw.value)
                    if found:
                        yield found


_WEAK_HASH = {"md5", "sha1", "md4", "md2"}
_WEAK_CIPHER_OWNERS = {"DES", "DES3", "ARC2", "ARC4", "RC2", "RC4", "Blowfish", "XOR"}


@python_detector
def _detect_weak_crypto(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in _WEAK_HASH:
            yield ctx.raw("KISA-SEC-04", node, message=f"취약한 해시 알고리즘 {func.id}()를 사용합니다.")
        elif isinstance(func, ast.Attribute) and func.attr in _WEAK_HASH and _attr_owner(func) in {"hashlib", ""}:
            yield ctx.raw("KISA-SEC-04", node, message=f"취약한 해시 알고리즘 {func.attr}()를 사용합니다.")
        elif isinstance(func, ast.Attribute) and func.attr == "new" and _attr_owner(func) == "hashlib" and node.args and isinstance(node.args[0], ast.Constant):
            if str(node.args[0].value).lower().replace("-", "") in {"md5", "sha1", "md4"}:
                yield ctx.raw("KISA-SEC-04", node)
        elif isinstance(func, ast.Attribute) and func.attr == "new" and _attr_owner(func) in _WEAK_CIPHER_OWNERS:
            yield ctx.raw("KISA-SEC-04", node, message=f"취약한 암호 알고리즘 {_attr_owner(func)}을(를) 사용합니다.")


_RANDOM_METHODS = {"random", "randint", "randrange", "choice", "choices", "sample", "shuffle", "uniform", "getrandbits"}
_SECURITY_CONTEXT = re.compile(
    r"(token|secret|key|password|passwd|pwd|salt|nonce|otp|session|csrf|auth|seed|verifier|cookie)", re.I
)


@python_detector
def _detect_weak_random(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        owner = node.func.value
        if not (isinstance(owner, ast.Name) and owner.id == "random" and node.func.attr in _RANDOM_METHODS):
            continue
        line = ctx.lines[node.lineno - 1] if 0 <= node.lineno - 1 < len(ctx.lines) else ""
        if _SECURITY_CONTEXT.search(line):
            yield ctx.raw("KISA-SEC-08", node)


_DESERIALIZE = {
    ("pickle", "loads"), ("pickle", "load"), ("cPickle", "loads"), ("cPickle", "load"),
    ("dill", "loads"), ("dill", "load"), ("marshal", "loads"), ("marshal", "load"),
    ("jsonpickle", "decode"), ("_pickle", "loads"), ("_pickle", "load"),
}
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}


@python_detector
def _detect_unsafe_deserialization(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        owner, attr = _attr_owner(node.func), node.func.attr
        if (owner, attr) == ("yaml", "load"):
            loader = next((k.value for k in node.keywords if k.arg == "Loader"), None)
            if loader is None and len(node.args) >= 2:
                loader = node.args[1]
            if _name_of(loader) not in _SAFE_YAML_LOADERS:
                yield ctx.raw("KISA-CODE-05", node)
        elif (owner, attr) in _DESERIALIZE:
            yield ctx.raw("KISA-CODE-05", node, message=f"안전하지 않은 역직렬화 호출 {owner}.{attr}()입니다.")


_PDB_OWNERS = {"pdb", "ipdb", "pudb", "pdbpp"}


@python_detector
def _detect_debug_code(ctx: PyContext):
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                    yield ctx.raw("KISA-CAPS-02", node, message="DEBUG = True 설정이 남아 있습니다.")
            continue
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "breakpoint":
            yield ctx.raw("KISA-CAPS-02", node, message="breakpoint() 디버그 호출이 남아 있습니다.")
        elif isinstance(func, ast.Attribute) and func.attr in {"set_trace", "post_mortem"} and _attr_owner(func) in _PDB_OWNERS:
            yield ctx.raw("KISA-CAPS-02", node, message=f"{_attr_owner(func)}.{func.attr}() 디버그 호출이 남아 있습니다.")
        elif isinstance(func, ast.Attribute) and func.attr == "run" and _kw_true(node, "debug"):
            yield ctx.raw("KISA-CAPS-02", node, message="debug=True 설정이 활성화되어 있습니다.")


_ERROR_SINK_NAMES = {
    "HttpResponse", "HttpResponseServerError", "HttpResponseBadRequest", "Response",
    "JsonResponse", "jsonify", "make_response", "render_template_string", "abort",
}
_ERROR_SINK_METHODS = {"send", "send_error", "json"}
_TRACEBACK_CALLS = {"format_exc", "print_exc", "format_exception", "format_tb"}


def _exposes_exception(node: ast.AST, exc_name: str | None) -> bool:
    for sub in ast.walk(node):
        if exc_name and isinstance(sub, ast.Name) and sub.id == exc_name:
            return True
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr in _TRACEBACK_CALLS:
            return True
    return False


@python_detector
def _detect_error_exposure(ctx: PyContext):
    for handler in [n for n in ast.walk(ctx.tree) if isinstance(n, ast.ExceptHandler)]:
        exc_name = handler.name
        for node in ast.walk(handler):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple) and len(node.value.elts) == 2:
                body, status = node.value.elts
                if isinstance(status, ast.Constant) and isinstance(status.value, int) and _exposes_exception(body, exc_name):
                    yield ctx.raw("KISA-ERR-01", node)
                continue
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_sink = (isinstance(func, ast.Name) and func.id in _ERROR_SINK_NAMES) or (
                isinstance(func, ast.Attribute) and func.attr in _ERROR_SINK_METHODS
            )
            if not is_sink:
                continue
            payload = list(node.args) + [k.value for k in node.keywords]
            if any(_exposes_exception(part, exc_name) for part in payload):
                yield ctx.raw("KISA-ERR-01", node)


_COMMENT_SECRET = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|token|credential|private[_-]?key)"
    r"\s*[:=]\s*[^\s'\"]{4,}",
    re.I,
)


def scan_secret_comments(source: str, markers: tuple[str, ...]) -> list[RawFinding]:
    """Language-agnostic sweep for credentials left in comments (KISA-SEC-11)."""
    findings: list[RawFinding] = []
    in_block = False
    for number, line in enumerate(source.splitlines(), 1):
        comment = None
        if in_block:
            comment = line.split("*/")[0] if "*/" in line else line
            in_block = "*/" not in line
        else:
            best = -1
            for marker in markers:
                pos = line.find(marker)
                if pos == -1 or (marker == "//" and pos > 0 and line[pos - 1] == ":"):
                    continue
                if best == -1 or pos < best:
                    best = pos
                    if marker == "/*":
                        segment = line[pos + 2:]
                        comment = segment.split("*/")[0] if "*/" in segment else segment
                        in_block = "*/" not in segment
                    else:
                        comment = line[pos + len(marker):]
        if comment and _COMMENT_SECRET.search(comment):
            findings.append(RawFinding(
                "KISA-SEC-11", number, RULE_SPECS["KISA-SEC-11"].message,
                line.strip(), TEXT_BASELINE_CONFIDENCE, 1,
            ))
    return findings


class PythonAnalyzer(Analyzer):
    language = "PYTHON"

    def analyze(self, source: str, file_path: str) -> list[RawFinding]:
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return []
        ctx = PyContext(source, tree)
        results: list[RawFinding] = []
        for detector in PY_DETECTORS:
            results.extend(detector(ctx))
        results.extend(scan_secret_comments(source, ("#",)))
        results.sort(key=lambda finding: (finding.line_number, finding.column))
        return results


# ---------------------------------------------------------------------------
# JavaScript / Java — regex baseline detectors
# ---------------------------------------------------------------------------

@dataclass
class TextRule:
    rule_code: str
    patterns: tuple[re.Pattern, ...]


def _compile(*patterns: str) -> tuple[re.Pattern, ...]:
    return tuple(re.compile(pattern, re.I) for pattern in patterns)


class TextAnalyzer(Analyzer):
    rules: tuple[TextRule, ...] = ()

    comment_markers: tuple[str, ...] = ("//", "/*")

    def analyze(self, source: str, file_path: str) -> list[RawFinding]:
        results: list[RawFinding] = []
        for number, line in enumerate(source.splitlines(), 1):
            for rule in self.rules:
                spec = RULE_SPECS.get(rule.rule_code)
                if spec and self.language not in spec.languages:
                    continue
                for pattern in rule.patterns:
                    match = pattern.search(line)
                    if match:
                        message = spec.message if spec else rule.rule_code
                        results.append(RawFinding(rule.rule_code, number, message, line.strip(), TEXT_BASELINE_CONFIDENCE, match.start() + 1))
                        break
        results.extend(scan_secret_comments(source, self.comment_markers))
        return results


class JavaScriptAnalyzer(TextAnalyzer):
    language = "JAVASCRIPT"
    rules = (
        TextRule("KISA-INPUT-01", _compile(
            r"\b(query|execute|exec|prepare|raw)\s*\(\s*[`'\"][^`'\"]*(SELECT|INSERT|UPDATE|DELETE)",
            r"\b(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*?(\+\s*\w|\$\{|`)",
        )),
        TextRule("KISA-INPUT-02", _compile(
            r"\beval\s*\(",
            r"new\s+Function\s*\(",
            r"\bsetTimeout\s*\(\s*['\"]",
        )),
        TextRule("KISA-INPUT-03", _compile(
            r"\bfs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|appendFile|unlink)\s*\([^)]*(\+|\$\{|req\.|request\.|\.\.[\\/])",
            r"\bpath\.(join|resolve)\s*\([^)]*(req\.|request\.|\+)",
        )),
        TextRule("KISA-INPUT-04", _compile(
            r"\.(innerHTML|outerHTML)\s*=",
            r"document\.write(ln)?\s*\(",
            r"\.insertAdjacentHTML\s*\(",
            r"dangerouslySetInnerHTML",
            r"\bres\.(send|write|end)\s*\([^)]*(req\.|\$\{|\+)",
        )),
        TextRule("KISA-INPUT-05", _compile(
            r"\.(exec|execSync)\s*\(\s*[`'\"]",
            r"\.(exec|execSync|spawn|spawnSync)\s*\([^)]*(\+|\$\{|req\.|request\.)",
        )),
        TextRule("KISA-SEC-06", _compile(
            r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|secret[_-]?key|token|auth[_-]?token)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        )),
        TextRule("KISA-SEC-04", _compile(
            r"createHash\s*\(\s*['\"](md5|sha1|md4)['\"]",
            r"createCipheriv?\s*\(\s*['\"](des|des3|rc4|rc2|.*-ecb)['\"]",
            r"\bCryptoJS\.(MD5|SHA1|DES|RC4|TripleDES)\b",
        )),
        TextRule("KISA-SEC-08", _compile(
            r"(token|secret|key|password|passwd|salt|nonce|otp|session|csrf|verifier)[\w$]*\s*[=:][^;\n]*Math\.random",
            r"Math\.random\s*\([^;\n]*(token|secret|key|password|salt|nonce|otp)",
        )),
        TextRule("KISA-ERR-01", _compile(
            r"\bres(ponse)?\.\w+\([^;\n]*\b\w*(err|error|exception|ex)\b\.(message|stack)\b",
            r"\bres(ponse)?\.\w+\([^;\n]*\.stack\b",
        )),
        TextRule("KISA-CODE-05", _compile(
            r"\bunserialize\s*\(",
            r"node-serialize",
        )),
        TextRule("KISA-CAPS-02", _compile(
            r"\bdebugger\b\s*;?",
            r"console\.debug\s*\(",
        )),
    )


class JavaAnalyzer(TextAnalyzer):
    language = "JAVA"
    rules = (
        TextRule("KISA-INPUT-01", _compile(
            r"\.(executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*[^)]*\"\s*\+",
            r"\"\s*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+",
        )),
        TextRule("KISA-INPUT-02", _compile(
            r"ScriptEngine[^;]*\.eval\s*\(",
            r"\bNashorn\b",
        )),
        TextRule("KISA-INPUT-03", _compile(
            r"new\s+File\s*\(\s*[^)]*\+",
            r"new\s+(FileInputStream|FileReader|FileOutputStream|FileWriter)\s*\(\s*[^)]*\+",
            r"Paths\.get\s*\(\s*[^)]*\+",
            r"\.\.[\\/]",
        )),
        TextRule("KISA-INPUT-04", _compile(
            r"response\.getWriter\(\)\s*\.\s*(print|println|write|append)\s*\(\s*[^)]*request\.",
            r"\bout\.(print|println|write)\s*\(\s*[^)]*request\.getParameter",
        )),
        TextRule("KISA-INPUT-05", _compile(
            r"Runtime\.getRuntime\(\)\s*\.\s*exec\s*\(",
            r"new\s+ProcessBuilder\s*\(",
        )),
        TextRule("KISA-SEC-06", _compile(
            r"\w*(password|passwd|pwd|secret|apikey|accesskey|token)\w*\s*=\s*\"[^\"]{4,}\"",
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        )),
        TextRule("KISA-SEC-04", _compile(
            r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1|MD4|MD2)\"",
            r"Cipher\.getInstance\s*\(\s*\"(DES|DESede|RC2|RC4|ARCFOUR)[^\"]*\"",
            r"Cipher\.getInstance\s*\(\s*\"[^\"]*/ECB/[^\"]*\"",
        )),
        TextRule("KISA-SEC-08", _compile(
            r"(token|secret|key|password|passwd|salt|nonce|otp|session|verifier)\w*\s*=\s*[^;\n]*new\s+(java\.util\.)?Random\b",
            r"new\s+(java\.util\.)?Random\b[^;\n]*(token|secret|key|password|salt|otp)",
        )),
        TextRule("KISA-CODE-05", _compile(
            r"new\s+ObjectInputStream\s*\(",
            r"\.readObject\s*\(\s*\)",
            r"new\s+XMLDecoder\s*\(",
        )),
        TextRule("KISA-ERR-01", _compile(
            r"(getWriter\(\)|response|out|pw|writer)[^;\n]*\.getMessage\s*\(\s*\)",
            r"\.printStackTrace\s*\(\s*(response|out|pw|writer|new\s+PrintWriter)",
        )),
        TextRule("KISA-CAPS-02", _compile(
            r"\.printStackTrace\s*\(\s*\)",
        )),
    )


class AnalyzerRegistry:
    def __init__(self):
        self._analyzers = {
            "PYTHON": PythonAnalyzer(),
            "JAVASCRIPT": JavaScriptAnalyzer(),
            "JAVA": JavaAnalyzer(),
        }

    def register(self, language: str, analyzer: Analyzer) -> None:
        self._analyzers[language.upper()] = analyzer

    def get(self, language: str) -> Analyzer:
        try:
            return self._analyzers[language.upper()]
        except KeyError:
            raise ValueError(f"지원하지 않는 분석 언어입니다: {language}")
