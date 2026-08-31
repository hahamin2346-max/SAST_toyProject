from collections import Counter
from pathlib import Path
from .analyzers import AnalyzerRegistry
from .auth import AuthError, TokenService, hash_password, verify_password
from .models import AnalysisRun, Finding, Project, Role, RunStatus, User, new_id, now
from .repositories import Repositories


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
        if not any(run.run_id == run_id for run in self.repos.project_runs(project_id)):
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

    def analyze_file(self, user: User, project_id: str) -> AnalysisRun:
        if user.role != Role.ADMIN:
            raise AuthorizationError("관리자만 분석을 실행할 수 있습니다.")
        project = self.require_project(user, project_id)
        run = AnalysisRun(new_id(), project.project_id, user.user_id, "AST", project.target_language)
        self.repos.add_run(run)
        run.status, run.started_at = RunStatus.RUNNING, now()
        try:
            source = Path(project.source_location).read_text(encoding="utf-8")
            raw_findings = self.analyzers.get(project.target_language).analyze(source, project.source_location)
            rules = {r.rule_code: r for r in self.repos.all_rules()}
            for raw in raw_findings:
                rule = rules.get(raw.rule_code)
                finding = Finding(new_id(), run.run_id, rule.rule_id if rule else None, raw.rule_code, rule.name if rule else raw.rule_code, project.target_language, rule.default_severity if rule else "MEDIUM", raw.confidence, project.source_location, raw.line_number, raw.message, raw.evidence, "입력 검증 및 안전한 API 사용을 적용하세요.")
                self.repos.add_finding(finding)
            counts = Counter(f.severity for f in self.repos.run_findings(run.run_id))
            run.summary = {"finding_count": len(raw_findings), "severity": dict(counts)}
            run.status = RunStatus.COMPLETED
        except Exception as exc:
            run.status, run.error_message = RunStatus.FAILED, str(exc)
        finally:
            run.ended_at = now()
            self.repos.update_run(run)
        return run
