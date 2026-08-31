import tempfile
import unittest
from pathlib import Path

from sast_platform.analyzers import AnalyzerRegistry
from sast_platform.auth import TokenService, hash_password
from sast_platform.catalog import load_kisa_catalog
from sast_platform.database import connect
from sast_platform.models import Role, User, new_id
from sast_platform.repositories import SQLiteRepositories
from sast_platform.services import Platform


class SQLitePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.database = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.database.close()
        self.path = Path(self.database.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_schema_seed_and_analysis_survive_reconnect(self):
        connection = connect(self.path)
        repos = SQLiteRepositories(connection)
        admin = repos.add_user(User(new_id(), "admin", hash_password("secret"), Role.ADMIN))
        for rule in load_kisa_catalog(Path(__file__).parent.parent / "Kisa_49_data.json"):
            repos.add_rule(rule)
        source = self.path.with_suffix(".py")
        source.write_text('PASSWORD = "secret"\nresult = eval(user_input)\n', encoding="utf-8")
        platform = Platform(repos, TokenService(b"test-secret"), AnalyzerRegistry())
        project = platform.create_project(admin, {"name": "sqlite-demo", "source_type": "PATH", "target_language": "PYTHON", "source_location": str(source)})
        run = platform.analyze_file(admin, project.project_id)

        self.assertEqual(49, len(repos.all_rules()))
        self.assertEqual("COMPLETED", run.status.value)
        self.assertGreaterEqual(len(repos.run_findings(run.run_id)), 1)
        connection.close()

        reopened = SQLiteRepositories(connect(self.path))
        self.assertEqual(1, len(reopened.all_projects()))
        self.assertEqual(1, len(reopened.project_runs(project.project_id)))
        self.assertGreaterEqual(len(reopened.run_findings(run.run_id)), 1)
        reopened.connection.close()
        source.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
