from collections import Counter
from pathlib import Path
import os
from .analyzers import AnalyzerRegistry
from .auth import AuthError, TokenService, hash_password, verify_password
from .models import AnalysisRun, Finding, Project, Role, RunStatus, User, new_id, now
from .repositories import Repositories
from .rules import RULE_SPECS


EXT_LANGUAGE = {
    ".py": "PYTHON",
    ".js": "JAVASCRIPT", ".jsx": "JAVASCRIPT", ".mjs": "JAVASCRIPT",
    ".ts": "JAVASCRIPT", ".tsx": "JAVASCRIPT",
    ".java": "JAVA",
}
MAX_FILES = 2000
MAX_FINDINGS = 5000


class AuthorizationError(Exception):
    pass


class Platform:
    def __init__(self, repos: Repositories, tokens: TokenService, analyzers: AnalyzerRegistry):
        self.repos, self.tokens, self.analyzers = repos, tokens, analyzers

    def authenticate(self, username: str, password: str) -> tuple[User, str]:
        user = self.repos.user_by_username(username)
        if not user or not user.is_active or not verify_password(password, user.password_hash):
            raise AuthError("아이디 또는 비밀번호가 올바르지 않습니다.")
        user.last_login_at = now()
        self.repos.update_user(user)
        return user, self.tokens.issue(user)

    def user(self, token: str) -> User:
        payload = self.tokens.verify(token)
        user = self.repos.get_user(payload["sub"])
        if not user or not user.is_active:
            raise AuthError("활성 사용자가 아닙니다.")
        return user

    def visible_projects(self, user: User) -> list[Project]:
        return [p for p in self.repos.all_projects() if user.role == Role.ADMIN or user.user_id in self.repos.project_member_ids(p.project_id)]

    def require_project(self, user: User, project_id: str) -> Project:
        project = self.repos.get_project(project_id)
        if not project or (user.role != Role.ADMIN and user.user_id not in self.repos.project_member_ids(project_id)):
            raise AuthorizationError("프로젝트를 찾을 수 없거나 접근 권한이 없습니다.")
        return project

    def create_project(self, user: User, data: dict) -> Project:
        if user.role != Role.ADMIN:
            raise AuthorizationError("관리자만 프로젝트를 생성할 수 있습니다.")
        required = ("name", "source_type", "target_language", "source_location")
        if any(not data.get(key) for key in required):
            raise ValueError("name, source_type, target_language, source_location은 필수입니다.")
        if any(p.name == data["name"] for p in self.repos.all_projects()):
            raise ValueError("프로젝트 이름은 중복될 수 없습니다.")
        project = Project(new_id(), data["name"], data.get("description", ""), data["source_type"], data["target_language"].upper(), data["source_location"], user.user_id)
        return self.repos.add_project(project)

    def delete_project(self, admin: User, project_id: str) -> Project:
        if admin.role != Role.ADMIN:
            raise AuthorizationError("관리자만 프로젝트를 삭제할 수 있습니다.")
        project = self.require_project(admin, project_id)
        self.repos.delete_project(project.project_id)
        return project

    def grant_access(self, admin: User, project_id: str, user_id: str) -> None:
        if admin.role != Role.ADMIN:
            raise AuthorizationError("관리자만 프로젝트 권한을 변경할 수 있습니다.")
        self.require_project(admin, project_id)
        if not self.repos.get_user(user_id):
            raise ValueError("사용자를 찾을 수 없습니다.")
        self.repos.grant_project_member(project_id, user_id)

    def revoke_access(self, admin: User, project_id: str, user_id: str) -> None:
        if admin.role != Role.ADMIN:
            raise AuthorizationError("관리자만 프로젝트 권한을 변경할 수 있습니다.")
        self.require_project(admin, project_id)
        self.repos.revoke_project_member(project_id, user_id)

    def project_runs(self, user: User, project_id: str) -> list[AnalysisRun]:
        self.require_project(user, project_id)
        return self.repos.project_runs(project_id)

    def run_findings(self, user: User, project_id: str, run_id: str) -> list[Finding]:
        self.require_project(user, project_id)
        if not any(str(run.run_id) == str(run_id) for run in self.repos.project_runs(project_id)):
            raise AuthorizationError("분석 실행을 찾을 수 없거나 접근 권한이 없습니다.")
        return self.repos.run_findings(run_id)

    def set_rule_active(self, admin: User, rule_id: str, is_active: bool):
        if admin.role != Role.ADMIN:
            raise AuthorizationError("관리자만 진단 규칙을 변경할 수 있습니다.")
        return self.repos.set_rule_active(rule_id, is_active)

    def users(self, admin: User) -> list[User]:
        if admin.role != Role.ADMIN:
            raise AuthorizationError("관리자만 사용자를 조회할 수 있습니다.")
        return self.repos.all_users()

    def _collect_files(self, source_path: Path) -> list[Path]:
        if source_path.is_dir():
            files = [p for p in sorted(source_path.rglob("*")) if p.is_file() and p.suffix.lower() in EXT_LANGUAGE]
        else:
            files = [source_path]
        return files[:MAX_FILES]

    def project_files(self, user: User, project_id: str) -> list[dict]:
        project = self.require_project(user, project_id)
        root = Path(project.source_location).resolve()
        if root.is_file():
            return [{"path": root.name, "language": EXT_LANGUAGE.get(root.suffix.lower())}]
        items: list[dict] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if root != resolved and root not in resolved.parents:
                continue
            items.append({
                "path": resolved.relative_to(root).as_posix(),
                "language": EXT_LANGUAGE.get(path.suffix.lower()),
            })
            if len(items) >= MAX_FILES:
                break
        return items

    def analyze_file(self, user: User, project_id: str) -> AnalysisRun:
        if user.role != Role.ADMIN:
            raise AuthorizationError("관리자만 분석을 실행할 수 있습니다.")
        project = self.require_project(user, project_id)
        run = AnalysisRun(new_id(), project.project_id, user.user_id, "AST", project.target_language)
        self.repos.add_run(run)
        run.status, run.started_at = RunStatus.RUNNING, now()
        try:
            source_path = Path(project.source_location)
            configured_langs = self.repos.all_languages()
            active_langs = (
                {lang["language_code"] for lang in configured_langs if lang["is_active"]}
                if configured_langs else None
            )
            rules_by_code = {rule.rule_code: rule for rule in self.repos.all_rules()}

            scanned, skipped = [], []
            raw_findings: list[tuple[Path, str, object]] = []
            for file_path in self._collect_files(source_path):
                language = EXT_LANGUAGE.get(file_path.suffix.lower())
                if language is None or (active_langs is not None and language not in active_langs):
                    skipped.append(str(file_path))
                    continue
                try:
                    source = file_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    skipped.append(str(file_path))
                    continue
                analyzer = self.analyzers.get(language)
                for raw in analyzer.analyze(source, str(file_path)):
                    raw_findings.append((file_path, language, raw))
                scanned.append(file_path)

            recorded = 0
            for file_path, language, raw in raw_findings[:MAX_FINDINGS]:
                spec = RULE_SPECS.get(raw.rule_code)
                if spec is None:
                    continue
                rule = rules_by_code.get(raw.rule_code)
                if rule is not None and not rule.is_active:
                    continue
                display_path = (
                    os.path.relpath(file_path, project.source_location)
                    if source_path.is_dir() else str(file_path)
                )
                finding = Finding(
                    new_id(), run.run_id, rule.rule_id if rule else None,
                    raw.rule_code, rule.name if rule else spec.name, language,
                    spec.severity, raw.confidence, display_path, raw.line_number,
                    raw.message or spec.message, raw.evidence, spec.recommendation,
                    raw_result={
                        "slug": spec.slug, "column": raw.column,
                        "kisa_num": spec.kisa_num, "kisa_code": spec.code,
                    },
                )
                self.repos.add_finding(finding)
                recorded += 1

            stored = self.repos.run_findings(run.run_id)
            run.summary = {
                "file_count": len(scanned),
                "finding_count": recorded,
                "severity": dict(Counter(f.severity for f in stored)),
                "by_rule": dict(Counter(f.rule_code_snapshot for f in stored)),
                "skipped_count": len(skipped),
            }
            run.status = RunStatus.COMPLETED
        except Exception as exc:
            run.status, run.error_message = RunStatus.FAILED, str(exc)
        finally:
            run.ended_at = now()
            self.repos.update_run(run)
        return run
