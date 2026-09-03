import http.client
import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from sast_platform.api import create_server


class UploadApiTests(unittest.TestCase):
    def test_zip_upload_registers_project_and_analyzes_files(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "test.sqlite")
            old_db = os.environ.get("SAST_DB_PATH")
            os.environ["SAST_DB_PATH"] = db_path
            server = create_server(port=0)
            self.server = server
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                login = self._request("POST", "/api/auth/login", {"Content-Type": "application/json"}, json.dumps({"username": "admin", "password": "change-me"}).encode())
                token = json.loads(login.read())["access_token"]
                archive = io.BytesIO()
                with zipfile.ZipFile(archive, "w") as zf:
                    zf.writestr("src/vulnerable.py", "eval(user_input)\nos.system(command)\n")
                boundary = "----sast-test"
                fields = [("name", "uploaded"), ("description", "zip test"), ("target_language", "PYTHON")]
                body = b""
                for name, value in fields:
                    body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
                body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"source_file\"; filename=\"sample.zip\"\r\nContent-Type: application/zip\r\n\r\n".encode() + archive.getvalue() + f"\r\n--{boundary}--\r\n".encode()
                response = self._request("POST", "/api/projects", {"Authorization": f"Bearer {token}", "Content-Type": f"multipart/form-data; boundary={boundary}"}, body)
                project_body = response.read()
                self.assertEqual(201, response.status, project_body)
                project = json.loads(project_body)

                files = self._request("GET", f"/api/projects/{project['project_id']}/files", {"Authorization": f"Bearer {token}"}, None)
                files_body = files.read()
                self.assertEqual(200, files.status, files_body)
                self.assertEqual(["src/vulnerable.py"], [item["path"] for item in json.loads(files_body)])

                run = self._request("POST", f"/api/projects/{project['project_id']}/analyze", {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, b"{}")
                run_body = run.read()
                self.assertEqual(202, run.status, run_body)
                run_id = json.loads(run_body)["run_id"]

                findings = self._request("GET", f"/api/projects/{project['project_id']}/runs/{run_id}/findings", {"Authorization": f"Bearer {token}"}, None)
                findings_body = findings.read()
                self.assertEqual(200, findings.status, findings_body)
                codes = {item["rule_code_snapshot"] for item in json.loads(findings_body)}
                self.assertIn("KISA-INPUT-02", codes)
                self.assertIn("KISA-INPUT-05", codes)
            finally:
                server.shutdown(); server.server_close(); server.platform.repos.connection.close(); thread.join(timeout=2)
                if old_db is None: os.environ.pop("SAST_DB_PATH", None)
                else: os.environ["SAST_DB_PATH"] = old_db

    def test_rules_endpoint_flags_implemented_and_keeps_active_set_coherent(self):
        from sast_platform.rules import RULE_SPECS
        with tempfile.TemporaryDirectory() as directory:
            old_db = os.environ.get("SAST_DB_PATH")
            os.environ["SAST_DB_PATH"] = str(Path(directory) / "test.sqlite")
            server = create_server(port=0)
            self.server = server
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                login = self._request("POST", "/api/auth/login", {"Content-Type": "application/json"}, json.dumps({"username": "admin", "password": "change-me"}).encode())
                token = json.loads(login.read())["access_token"]
                rules = json.loads(self._request("GET", "/api/rules", {"Authorization": f"Bearer {token}"}, None).read())
                implemented = {r["rule_code"] for r in rules if r["is_implemented"]}
                active = {r["rule_code"] for r in rules if r["is_active"]}
                self.assertEqual(set(RULE_SPECS), implemented)
                self.assertEqual(set(RULE_SPECS), active)
                self.assertTrue(active <= implemented)
            finally:
                server.shutdown(); server.server_close(); server.platform.repos.connection.close(); thread.join(timeout=2)
                if old_db is None: os.environ.pop("SAST_DB_PATH", None)
                else: os.environ["SAST_DB_PATH"] = old_db

    def _request(self, method, path, headers, body):
        host, port = self.server.server_address
        connection = http.client.HTTPConnection(host, port)
        connection.request(method, path, body=body, headers=headers)
        return connection.getresponse()
