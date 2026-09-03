import tempfile
import unittest
from pathlib import Path
from sast_platform.analyzers import AnalyzerRegistry
from sast_platform.auth import TokenService, hash_password, verify_password
from sast_platform.catalog import load_kisa_catalog
from sast_platform.models import Role, User, new_id
from sast_platform.repositories import Repositories
from sast_platform.services import Platform, AuthorizationError


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.repos = Repositories()
        self.admin = User(new_id(), "admin", hash_password("secret"), Role.ADMIN)
        self.user = User(new_id(), "user", hash_password("secret"), Role.USER)
        self.repos.users.add(self.admin, self.admin.user_id); self.repos.users.add(self.user, self.user.user_id)
        self.repos.rules.add(load_kisa_catalog(Path(__file__).parent.parent / "Kisa_49_data.json")[0], "rule")
        self.platform = Platform(self.repos, TokenService(b"test-secret"), AnalyzerRegistry())

    def test_password_and_token(self):
        self.assertTrue(verify_password("secret", self.admin.password_hash)); self.assertFalse(verify_password("bad", self.admin.password_hash))
        _, token = self.platform.authenticate("admin", "secret"); self.assertEqual(self.admin.user_id, self.platform.user(token).user_id)

    def test_catalog_has_49_rules(self):
        self.assertEqual(49, len(load_kisa_catalog(Path(__file__).parent.parent / "Kisa_49_data.json")))

    def test_role_and_analysis(self):
        with self.assertRaises(AuthorizationError): self.platform.create_project(self.user, {})
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write('PASSWORD = "secret"\nresult = eval(user_input)\n'); path = f.name
        project = self.platform.create_project(self.admin, {"name": "demo", "source_type": "PATH", "target_language": "PYTHON", "source_location": path})
        run = self.platform.analyze_file(self.admin, project.project_id)
        self.assertEqual("COMPLETED", run.status.value); self.assertEqual(2, run.summary["finding_count"])

    def test_admin_deletes_project_and_user_loses_visibility(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write("x = 1\n"); path = f.name
        project = self.platform.create_project(self.admin, {"name": "trash", "source_type": "PATH", "target_language": "PYTHON", "source_location": path})
        self.platform.grant_access(self.admin, project.project_id, self.user.user_id)
        self.assertEqual(["trash"], [p.name for p in self.platform.visible_projects(self.user)])
        with self.assertRaises(AuthorizationError):
            self.platform.delete_project(self.user, project.project_id)
        self.platform.delete_project(self.admin, project.project_id)
        self.assertEqual([], self.platform.visible_projects(self.user))
        self.assertIsNone(self.repos.get_project(project.project_id))

    def test_directory_analysis_detects_requested_input_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "vulnerable.py"
            source.write_text("import os\nfrom flask import render_template_string\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\ncursor.execute(query)\neval(user_input)\nopen(base + user_path)\nrender_template_string(user_html)\nos.system(command)\n", encoding="utf-8")
            project = self.platform.create_project(self.admin, {"name": "multi-file", "source_type": "PATH", "target_language": "PYTHON", "source_location": directory})
            run = self.platform.analyze_file(self.admin, project.project_id)
            codes = {finding.rule_code_snapshot for finding in self.repos.run_findings(run.run_id)}
            self.assertTrue({"KISA-INPUT-01", "KISA-INPUT-02", "KISA-INPUT-03", "KISA-INPUT-04", "KISA-INPUT-05"}.issubset(codes))
            self.assertEqual(1, run.summary["file_count"])


if __name__ == "__main__": unittest.main()
