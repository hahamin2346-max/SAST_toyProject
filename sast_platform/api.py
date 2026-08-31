import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote
from .analyzers import AnalyzerRegistry
from .auth import AuthError, TokenService, hash_password
from .catalog import load_kisa_catalog
from .models import Role, User, new_id
from .database import connect
from .repositories import SQLiteRepositories
from .services import AuthorizationError, Platform


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
        for rule in load_kisa_catalog(Path(__file__).parent.parent / "Kisa_49_data.json"):
            repos.add_rule(rule)
    if not repos.all_languages():
        for code, name in (("PYTHON", "Python"), ("JAVASCRIPT", "Javascript"), ("JAVA", "Java")):
            repos.add_language(code, name)
    return Platform(repos, TokenService(os.getenv("SAST_TOKEN_SECRET", "development-only-secret").encode()), AnalyzerRegistry())


def create_server(host="127.0.0.1", port=8000):
    platform = create_platform()
    web_root = (Path(__file__).parent.parent / "web").resolve()

    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status, payload):
            body = json.dumps(_json(payload), ensure_ascii=False).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def body(self):
            return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
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
                if self.path == "/api/projects": return self.send_json(200, platform.visible_projects(user))
                if self.path == "/api/rules": return self.send_json(200, platform.repos.all_rules())
                if self.path == "/api/languages": return self.send_json(200, platform.repos.all_languages())
                if self.path == "/api/users": return self.send_json(200, platform.users(user))
                if self.path.startswith("/api/projects/"):
                    parts = self.path.split("/")
                    project = platform.require_project(user, parts[3])
                    if len(parts) == 4: return self.send_json(200, project)
                    if len(parts) == 5 and parts[4] == "runs": return self.send_json(200, platform.project_runs(user, project.project_id))
                    if len(parts) == 7 and parts[4] == "runs" and parts[6] == "findings": return self.send_json(200, platform.run_findings(user, project.project_id, parts[5]))
                    if len(parts) == 5 and parts[4] == "members": return self.send_json(200, [u for u in platform.users(user) if u.user_id in platform.repos.project_member_ids(project.project_id)])
                self.send_json(404, {"error": "not found"})
            except (AuthError, AuthorizationError) as exc: self.send_json(401, {"error": str(exc)})
            except Exception as exc: self.send_json(400, {"error": str(exc)})
        def do_POST(self):
            try:
                data = self.body()
                if self.path == "/api/auth/login":
                    user, token = platform.authenticate(data.get("username", ""), data.get("password", "")); return self.send_json(200, {"access_token": token, "token_type": "Bearer", "user": user})
                user = self.current_user()
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
                self.send_json(404, {"error": "not found"})
            except AuthError as exc: self.send_json(401, {"error": str(exc)})
            except AuthorizationError as exc: self.send_json(403, {"error": str(exc)})
            except Exception as exc: self.send_json(400, {"error": str(exc)})
        def log_message(self, *_): pass
    return ThreadingHTTPServer((host, port), Handler)
