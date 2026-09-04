import json
import mimetypes
import os
import io
import shutil
import uuid
import zipfile
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote
from .analyzers import AnalyzerRegistry
from .auth import AuthError, TokenService, hash_password
from .catalog import load_kisa_catalog
from .models import Role, Rule, User, new_id
from .database import connect
from .repositories import SQLiteRepositories
from .rules import RULE_SPECS
from .services import AuthorizationError, EXT_LANGUAGE, Platform


def _json(value):
    if hasattr(value, "isoformat"): return value.isoformat()
    if hasattr(value, "value"): return value.value
    if hasattr(value, "__dict__"): return {k: _json(v) for k, v in value.__dict__.items()}
    if isinstance(value, dict): return {k: _json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [_json(v) for v in value]
    return value


def create_platform() -> Platform:
    repos = SQLiteRepositories(connect())
    admin = User(new_id(), "admin", hash_password(os.getenv("SAST_ADMIN_PASSWORD", "change-me")), Role.ADMIN)
    if not repos.user_by_username(admin.username):
        repos.add_user(admin)
    if not repos.all_rules():
        seeded = set()
        for rule in load_kisa_catalog(Path(__file__).parent.parent / "Kisa_49_data.json"):
            rule.is_active = rule.rule_code in RULE_SPECS
            repos.add_rule(rule)
            seeded.add(rule.rule_code)
        # Every implemented rule gets a toggleable row even if the KISA catalog
        # file does not list it yet, so future rules stay manageable from the UI.
        for code, spec in RULE_SPECS.items():
            if code not in seeded:
                repos.add_rule(Rule(new_id(), code, spec.name, spec.description, spec.category, spec.kisa_num, spec.reference, spec.severity, True))
    # Only rules with a detector implementation can be active; a rule without one
    # would silently produce nothing, so keep the stored state coherent on boot.
    for rule in repos.all_rules():
        if rule.is_active and rule.rule_code not in RULE_SPECS:
            repos.set_rule_active(rule.rule_id, False)
    if not repos.all_languages():
        for code, name in (("PYTHON", "Python"), ("JAVASCRIPT", "Javascript"), ("JAVA", "Java")):
            repos.add_language(code, name)
    return Platform(repos, TokenService(os.getenv("SAST_TOKEN_SECRET", "development-only-secret").encode()), AnalyzerRegistry())


def create_server(host="0.0.0.0", port=8000):
    platform = create_platform()
    web_root = (Path(__file__).parent.parent / "web").resolve()

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, payload):
            body = json.dumps(_json(payload), ensure_ascii=False).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def body(self):
            return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        def upload_project(self, user):
            if user.role != Role.ADMIN:
                raise AuthorizationError("관리자만 프로젝트를 등록할 수 있습니다.")
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > 50 * 1024 * 1024:
                raise ValueError("ZIP 파일은 50MB 이하만 업로드할 수 있습니다.")
            content_type = self.headers.get("Content-Type", "")
            from email.parser import BytesParser
            from email.policy import default
            payload = (f"Content-Type: {content_type}\r\n\r\n").encode() + self.rfile.read(length)
            message = BytesParser(policy=default).parsebytes(payload)
            fields, upload = {}, None
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                if name == "source_file": upload = part
                elif name:
                    raw = part.get_payload(decode=True)
                    fields[name] = raw.decode("utf-8", "replace") if raw is not None else part.get_content()
            if not upload or not upload.get_filename():
                raise ValueError("ZIP 파일을 선택해 주세요.")
            if not upload.get_filename().lower().endswith(".zip"):
                raise ValueError("ZIP 파일만 업로드할 수 있습니다.")
            archive = upload.get_payload(decode=True) or b""
            workspace = Path(__file__).parent.parent / "data" / "workspaces" / uuid.uuid4().hex
            workspace.mkdir(parents=True, exist_ok=False)
            member_names = []
            try:
                with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                    members = [info for info in zf.infolist() if not info.is_dir()]
                    if len(members) > 5000 or sum(info.file_size for info in members) > 500 * 1024 * 1024:
                        raise ValueError("ZIP 내부 파일 수 또는 압축 해제 용량 제한을 초과했습니다.")
                    root = workspace.resolve()
                    for info in members:
                        target = (workspace / info.filename).resolve()
                        if root not in target.parents:
                            raise ValueError("허용되지 않은 ZIP 경로가 포함되어 있습니다.")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(zf.read(info))
                        member_names.append(info.filename)
            except Exception:
                shutil.rmtree(workspace, ignore_errors=True)
                raise
            languages = Counter(EXT_LANGUAGE.get(Path(n).suffix.lower()) for n in member_names)
            languages.pop(None, None)
            auto_language = (fields.get("target_language", "").upper()
                             or (languages.most_common(1)[0][0] if languages else "PYTHON"))
            base_name = (fields.get("name", "").strip()
                         or Path(upload.get_filename()).stem or "uploaded-project")
            existing = {project.name for project in platform.repos.all_projects()}
            name, suffix = base_name, 2
            while name in existing:
                name, suffix = f"{base_name}-{suffix}", suffix + 1
            data = {"name": name, "description": fields.get("description", ""), "source_type": "UPLOAD", "target_language": auto_language, "source_location": str(workspace)}
            try:
                return self.send_json(201, platform.create_project(user, data))
            except Exception:
                shutil.rmtree(workspace, ignore_errors=True)
                raise
        def current_user(self):
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "): raise AuthError("인증이 필요합니다.")
            return platform.user(auth[7:])
        def do_GET(self):
            try:
                if self.path == "/health": return self.send_json(200, {"status": "ok"})
                if self.path == "/favicon.ico": self.send_response(204); self.send_header("Cache-Control", "no-store"); self.end_headers(); return
                request_path = unquote(self.path)
                if request_path == "/" or request_path in ("/index.html", "/styles.css", "/overrides.css", "/app.js", "/kisa-guide.txt"):
                    requested = "index.html" if request_path == "/" else ("kisa보안가이드 정리.txt" if request_path == "/kisa-guide.txt" else request_path.lstrip("/"))
                    static_root = web_root.parent if requested == "kisa보안가이드 정리.txt" else web_root
                    static_path = (static_root / requested).resolve()
                    if static_root not in static_path.parents: return self.send_json(404, {"error": "not found"})
                    if not static_path.is_file(): return self.send_json(404, {"error": "not found"})
                    body = static_path.read_bytes(); self.send_response(200); self.send_header("Content-Type", mimetypes.guess_type(str(static_path))[0] or "application/octet-stream"); self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
                user = self.current_user()
                if self.path == "/api/me": return self.send_json(200, user)
                if self.path == "/api/projects": return self.send_json(200, platform.visible_projects(user))
                if self.path == "/api/rules": return self.send_json(200, [{**_json(rule), "is_implemented": rule.rule_code in RULE_SPECS} for rule in platform.repos.all_rules()])
                if self.path == "/api/languages": return self.send_json(200, platform.repos.all_languages())
                if self.path == "/api/users": return self.send_json(200, platform.users(user))
                if self.path.startswith("/api/projects/"):
                    parts = self.path.split("/")
                    project = platform.require_project(user, parts[3])
                    if len(parts) == 4: return self.send_json(200, project)
                    if len(parts) == 5 and parts[4] == "files": return self.send_json(200, platform.project_files(user, project.project_id))
                    if len(parts) == 5 and parts[4] == "runs": return self.send_json(200, platform.project_runs(user, project.project_id))
                    if len(parts) == 7 and parts[4] == "runs" and parts[6] == "findings": return self.send_json(200, platform.run_findings(user, project.project_id, parts[5]))
                    if len(parts) == 5 and parts[4] == "members": return self.send_json(200, [u for u in platform.users(user) if u.user_id in platform.repos.project_member_ids(project.project_id)])
                self.send_json(404, {"error": "not found"})
            except AuthError as exc: self.send_json(401, {"error": str(exc)})
            except AuthorizationError as exc: self.send_json(403, {"error": str(exc)})
            except Exception as exc: self.send_json(400, {"error": str(exc)})
        def do_POST(self):
            try:
                if self.path == "/api/auth/login":
                    data = self.body()
                    user, token = platform.authenticate(data.get("username", ""), data.get("password", "")); return self.send_json(200, {"access_token": token, "token_type": "Bearer", "user": user})
                user = self.current_user()
                if self.path == "/api/projects" and self.headers.get("Content-Type", "").startswith("multipart/form-data"):
                    return self.upload_project(user)
                data = self.body()
                if self.path == "/api/projects": return self.send_json(201, platform.create_project(user, data))
                if self.path == "/api/languages": return self.send_json(201, platform.repos.add_language(data["language_code"].upper(), data["display_name"]))
                if self.path.startswith("/api/projects/") and self.path.endswith("/members"):
                    parts = self.path.split("/"); platform.grant_access(user, parts[3], data["user_id"]); return self.send_json(204, {})
                if self.path.startswith("/api/projects/") and self.path.endswith("/analyze"):
                    run = platform.analyze_file(user, self.path.split("/")[3]); return self.send_json(202, run)
                self.send_json(404, {"error": "not found"})
            except AuthError as exc: self.send_json(401, {"error": str(exc)})
            except AuthorizationError as exc: self.send_json(403, {"error": str(exc)})
            except Exception as exc: self.send_json(400, {"error": str(exc)})
        def do_PATCH(self):
            try:
                data = self.body(); user = self.current_user()
                if self.path.startswith("/api/rules/"):
                    return self.send_json(200, platform.set_rule_active(user, self.path.split("/")[3], bool(data.get("is_active"))))
                if self.path.startswith("/api/languages/"):
                    return self.send_json(200, platform.repos.set_language_active(self.path.split("/")[3].upper(), bool(data.get("is_active"))))
                self.send_json(404, {"error": "not found"})
            except AuthError as exc: self.send_json(401, {"error": str(exc)})
            except AuthorizationError as exc: self.send_json(403, {"error": str(exc)})
            except Exception as exc: self.send_json(400, {"error": str(exc)})
        def do_DELETE(self):
            try:
                user = self.current_user()
                if self.path.startswith("/api/projects/") and self.path.endswith("/members"):
                    parts = self.path.split("/"); platform.revoke_access(user, parts[3], self.body().get("user_id")); return self.send_json(204, {})
                if self.path.startswith("/api/projects/") and self.path.count("/") == 3:
                    project = platform.delete_project(user, self.path.split("/")[3])
                    workspaces = (Path(__file__).parent.parent / "data" / "workspaces").resolve()
                    location = Path(project.source_location).resolve()
                    if project.source_type == "UPLOAD" and workspaces in location.parents:
                        shutil.rmtree(location, ignore_errors=True)
                    return self.send_json(204, {})
                self.send_json(404, {"error": "not found"})
            except AuthError as exc: self.send_json(401, {"error": str(exc)})
            except AuthorizationError as exc: self.send_json(403, {"error": str(exc)})
            except Exception as exc: self.send_json(400, {"error": str(exc)})
        def log_message(self, *_): pass
    # Single-threaded on purpose: SQLiteRepositories shares one connection, and the
    # frontend issues many requests in parallel. Serving them one at a time keeps that
    # connection safe. Swap for a per-thread connection pool before real concurrency.
    server = HTTPServer((host, port), Handler)
    server.platform = platform
    return server
