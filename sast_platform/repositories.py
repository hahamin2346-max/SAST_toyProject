import json
import sqlite3
from collections import defaultdict
from datetime import datetime
from typing import Generic, TypeVar
from .models import AnalysisRun, Finding, Project, Role, Rule, RunStatus, User

T = TypeVar("T")


class InMemoryRepository(Generic[T]):
    def __init__(self):
        self.items: dict[str, T] = {}

    def add(self, item: T, key: str) -> T:
        self.items[key] = item
        return item

    def get(self, key: str) -> T | None:
        return self.items.get(key)

    def all(self) -> list[T]:
        return list(self.items.values())


class Repositories:
    def __init__(self):
        self.users = InMemoryRepository[User]()
        self.projects = InMemoryRepository[Project]()
        self.rules = InMemoryRepository[Rule]()
        self.runs = InMemoryRepository[AnalysisRun]()
        self.findings = InMemoryRepository[Finding]()
        self.project_members: dict[str, set[str]] = defaultdict(set)

    def user_by_username(self, username: str) -> User | None:
        return next((u for u in self.users.all() if u.username == username), None)

    def project_runs(self, project_id: str) -> list[AnalysisRun]:
        return [r for r in self.runs.all() if r.project_id == project_id]

    def run_findings(self, run_id: str) -> list[Finding]:
        return [f for f in self.findings.all() if f.run_id == run_id]

    # The service layer uses these names for both in-memory tests and SQLite.
    def get_user(self, user_id: str | int) -> User | None: return self.users.get(user_id)
    def all_users(self) -> list[User]: return self.users.all()
    def add_user(self, user: User) -> User: return self.users.add(user, user.user_id)
    def update_user(self, user: User) -> User: return user
    def all_projects(self) -> list[Project]: return self.projects.all()
    def get_project(self, project_id: str | int) -> Project | None: return self.projects.get(project_id)
    def add_project(self, project: Project) -> Project: return self.projects.add(project, project.project_id)
    def delete_project(self, project_id: str | int) -> None:
        self.projects.items.pop(project_id, None); self.project_members.pop(project_id, None)
    def all_rules(self) -> list[Rule]: return self.rules.all()
    def add_rule(self, rule: Rule) -> Rule: return self.rules.add(rule, rule.rule_id)
    def add_run(self, run: AnalysisRun) -> AnalysisRun: return self.runs.add(run, run.run_id)
    def update_run(self, run: AnalysisRun) -> AnalysisRun: return run
    def add_finding(self, finding: Finding) -> Finding: return self.findings.add(finding, finding.finding_id)
    def project_member_ids(self, project_id: str | int) -> set[str]: return self.project_members[project_id]
    def grant_project_member(self, project_id: str | int, user_id: str | int) -> None: self.project_members[project_id].add(user_id)
    def revoke_project_member(self, project_id: str | int, user_id: str | int) -> None: self.project_members[project_id].discard(user_id)
    def set_rule_active(self, rule_id: str | int, is_active: bool) -> Rule:
        rule = self.rules.get(rule_id); rule.is_active = is_active; return rule
    def all_languages(self) -> list[dict]: return [{"language_code": "PYTHON", "display_name": "Python", "is_active": True}]
    def add_language(self, language_code: str, display_name: str) -> dict: return {"language_code": language_code, "display_name": display_name, "is_active": True}
    def set_language_active(self, language_code: str, is_active: bool) -> dict: return {"language_code": language_code, "display_name": language_code.title(), "is_active": is_active}


class SQLiteRepositories:
    """SQLite-backed equivalent of Repositories, kept on the same service boundary."""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def _insert_id(self, table: str, columns: tuple[str, ...], values: tuple[object, ...], item: object) -> object:
        placeholders = ", ".join("?" for _ in columns)
        cursor = self.connection.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})", values
        )
        self.connection.commit()
        item_id = cursor.lastrowid
        return item_id

    @staticmethod
    def _time(value: datetime | None) -> str | None:
        return value.isoformat() if value else None

    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        return datetime.fromisoformat(value) if value else None

    def add_user(self, user: User) -> User:
        item_id = self._insert_id("users", ("username", "password_hash", "role", "is_active", "created_at", "updated_at", "last_login_at"), (user.username, user.password_hash, user.role.value, int(user.is_active), self._time(user.created_at), self._time(user.updated_at), self._time(user.last_login_at)), user)
        user.user_id = item_id
        return user

    def update_user(self, user: User) -> User:
        self.connection.execute("UPDATE users SET is_active = ?, role = ?, last_login_at = ?, updated_at = ? WHERE user_id = ?", (int(user.is_active), user.role.value, self._time(user.last_login_at), self._time(user.updated_at), user.user_id)); self.connection.commit()
        return user

    def user_by_username(self, username: str) -> User | None:
        row = self.connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return self._user(row) if row else None

    def get_user(self, user_id: str | int) -> User | None:
        row = self.connection.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
        return self._user(row) if row else None

    def all_users(self) -> list[User]:
        return [self._user(row) for row in self.connection.execute("SELECT * FROM users ORDER BY user_id")]

    def _user(self, row: sqlite3.Row) -> User:
        return User(row["user_id"], row["username"], row["password_hash"], Role(row["role"]), bool(row["is_active"]), self._parse_time(row["created_at"]), self._parse_time(row["updated_at"]), self._parse_time(row["last_login_at"]))

    def add_project(self, project: Project) -> Project:
        cursor = self.connection.execute("INSERT INTO projects (name, description, source_type, target_language, source_location, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (project.name, project.description, project.source_type, project.target_language, project.source_location, project.created_by, self._time(project.created_at), self._time(project.updated_at)))
        self.connection.commit(); project.project_id = cursor.lastrowid
        return project

    def get_project(self, project_id: str | int) -> Project | None:
        row = self.connection.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,)).fetchone()
        return self._project(row) if row else None

    def delete_project(self, project_id: str | int) -> None:
        self.connection.execute("DELETE FROM projects WHERE project_id = ?", (project_id,))
        self.connection.commit()

    def all_projects(self) -> list[Project]:
        return [self._project(row) for row in self.connection.execute("SELECT * FROM projects ORDER BY project_id")]

    def _project(self, row: sqlite3.Row) -> Project:
        return Project(row["project_id"], row["name"], row["description"], row["source_type"], row["target_language"], row["source_location"], row["created_by"], self._parse_time(row["created_at"]), self._parse_time(row["updated_at"]))

    def add_rule(self, rule: Rule) -> Rule:
        timestamp = self._time(datetime.now().astimezone())
        cursor = self.connection.execute("INSERT INTO rules (rule_code, name, description, category, kisa_num, reference_info, default_severity, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (rule.rule_code, rule.name, rule.description, rule.category, rule.kisa_num, rule.reference_info, rule.default_severity, int(rule.is_active), timestamp, timestamp))
        self.connection.commit(); rule.rule_id = cursor.lastrowid
        return rule

    def all_rules(self) -> list[Rule]:
        return [Rule(row["rule_id"], row["rule_code"], row["name"], row["description"], row["category"], row["kisa_num"], row["reference_info"], row["default_severity"], bool(row["is_active"])) for row in self.connection.execute("SELECT * FROM rules ORDER BY kisa_num, rule_id")]

    def add_run(self, run: AnalysisRun) -> AnalysisRun:
        cursor = self.connection.execute("INSERT INTO analysis_runs (project_id, executed_by, analysis_mode, language, status, error_message, summary_json, started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (run.project_id, run.executed_by, run.analysis_mode, run.language, run.status.value, run.error_message, json.dumps(run.summary), self._time(run.started_at), self._time(run.ended_at)))
        self.connection.commit(); run.run_id = cursor.lastrowid
        return run

    def update_run(self, run: AnalysisRun) -> AnalysisRun:
        self.connection.execute("UPDATE analysis_runs SET status = ?, error_message = ?, summary_json = ?, started_at = ?, ended_at = ? WHERE run_id = ?", (run.status.value, run.error_message, json.dumps(run.summary), self._time(run.started_at), self._time(run.ended_at), run.run_id)); self.connection.commit()
        return run

    def add_finding(self, finding: Finding) -> Finding:
        cursor = self.connection.execute("INSERT INTO findings (run_id, rule_id, language, file_path, line_number, evidence, message, recommendation, severity_snapshot, confidence, rule_code_snapshot, rule_name_snapshot, raw_result_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (finding.run_id, finding.rule_id, finding.language, finding.file_path, finding.line_number, finding.evidence, finding.message, finding.recommendation, finding.severity, finding.confidence, finding.rule_code_snapshot, finding.rule_name_snapshot, json.dumps(finding.raw_result), self._time(datetime.now())))
        self.connection.commit(); finding.finding_id = cursor.lastrowid
        return finding

    def project_member_ids(self, project_id: str | int) -> set[int]:
        return {row["user_id"] for row in self.connection.execute("SELECT user_id FROM project_members WHERE project_id = ?", (project_id,))}

    def grant_project_member(self, project_id: str | int, user_id: str | int) -> None:
        self.connection.execute("INSERT OR IGNORE INTO project_members (project_id, user_id, granted_at) VALUES (?, ?, ?)", (project_id, user_id, datetime.now().astimezone().isoformat())); self.connection.commit()

    def revoke_project_member(self, project_id: str | int, user_id: str | int) -> None:
        self.connection.execute("DELETE FROM project_members WHERE project_id = ? AND user_id = ?", (project_id, user_id)); self.connection.commit()

    def set_rule_active(self, rule_id: str | int, is_active: bool) -> Rule:
        self.connection.execute("UPDATE rules SET is_active = ?, updated_at = ? WHERE rule_id = ?", (int(is_active), datetime.now().astimezone().isoformat(), rule_id)); self.connection.commit()
        row = self.connection.execute("SELECT * FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
        if not row: raise ValueError("규칙을 찾을 수 없습니다.")
        return Rule(row["rule_id"], row["rule_code"], row["name"], row["description"], row["category"], row["kisa_num"], row["reference_info"], row["default_severity"], bool(row["is_active"]))

    def all_languages(self) -> list[dict]:
        return [dict(row) | {"is_active": bool(row["is_active"])} for row in self.connection.execute("SELECT * FROM languages ORDER BY display_name")]

    def add_language(self, language_code: str, display_name: str) -> dict:
        timestamp = datetime.now().astimezone().isoformat()
        self.connection.execute("INSERT INTO languages (language_code, display_name, is_active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)", (language_code, display_name, timestamp, timestamp)); self.connection.commit()
        return {"language_code": language_code, "display_name": display_name, "is_active": True}

    def set_language_active(self, language_code: str, is_active: bool) -> dict:
        self.connection.execute("UPDATE languages SET is_active = ?, updated_at = ? WHERE language_code = ?", (int(is_active), datetime.now().astimezone().isoformat(), language_code)); self.connection.commit()
        row = self.connection.execute("SELECT language_code, display_name, is_active FROM languages WHERE language_code = ?", (language_code,)).fetchone()
        if not row: raise ValueError("언어를 찾을 수 없습니다.")
        return dict(row) | {"is_active": bool(row["is_active"])}

    def visible_projects(self, user: User) -> list[Project]:
        if user.role == Role.ADMIN:
            return self.all_projects()
        return [project for project in self.all_projects() if user.user_id in self.project_member_ids(project.project_id)]

    def project_runs(self, project_id: str | int) -> list[AnalysisRun]:
        rows = self.connection.execute("SELECT * FROM analysis_runs WHERE project_id = ? ORDER BY run_id DESC", (project_id,))
        return [AnalysisRun(row["run_id"], row["project_id"], row["executed_by"], row["analysis_mode"], row["language"], RunStatus(row["status"]), row["error_message"], json.loads(row["summary_json"]), self._parse_time(row["started_at"]), self._parse_time(row["ended_at"])) for row in rows]

    def run_findings(self, run_id: str | int) -> list[Finding]:
        rows = self.connection.execute("SELECT * FROM findings WHERE run_id = ? ORDER BY finding_id", (run_id,))
        return [Finding(row["finding_id"], row["run_id"], row["rule_id"], row["rule_code_snapshot"], row["rule_name_snapshot"], row["language"], row["severity_snapshot"], row["confidence"], row["file_path"], row["line_number"], row["message"], row["evidence"], row["recommendation"], json.loads(row["raw_result_json"])) for row in rows]
