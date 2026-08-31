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


if __name__ == "__main__": unittest.main()
