import re
import tempfile
import unittest
from pathlib import Path

from sast_platform.analyzers import AnalyzerRegistry, JavaAnalyzer, JavaScriptAnalyzer, PythonAnalyzer
from sast_platform.auth import TokenService, hash_password
from sast_platform.models import Role, Rule, User, new_id
from sast_platform.repositories import Repositories
from sast_platform.rules import RULE_SPECS
from sast_platform.services import Platform

SAMPLES = Path(__file__).parent.parent / "testSample"


def codes(findings):
    return {f.rule_code for f in findings}


IMPLEMENTED_RULES = {
    "KISA-INPUT-01", "KISA-INPUT-02", "KISA-INPUT-03", "KISA-INPUT-04", "KISA-INPUT-05",
    "KISA-SEC-04", "KISA-SEC-06", "KISA-SEC-08", "KISA-SEC-11",
    "KISA-ERR-01", "KISA-CODE-05", "KISA-CAPS-02",
}


class RuleSpecTests(unittest.TestCase):
    def test_rule_spec_catalog(self):
        self.assertEqual(IMPLEMENTED_RULES, set(RULE_SPECS))

    def test_slugs_and_kisa_numbers_unique(self):
        slugs = [spec.slug for spec in RULE_SPECS.values()]
        nums = [spec.kisa_num for spec in RULE_SPECS.values()]
        self.assertEqual(len(slugs), len(set(slugs)))
        self.assertEqual(len(nums), len(set(nums)))

    def test_spec_shape(self):
        for spec in RULE_SPECS.values():
            self.assertRegex(spec.slug, r"^\d{2}_[a-z_]+$")
            self.assertIn(spec.severity, {"HIGH", "MEDIUM", "LOW"})
            self.assertTrue(0 < spec.confidence <= 1)
            self.assertTrue(spec.recommendation and spec.message)


class PythonAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = PythonAnalyzer()

    def analyze(self, source):
        return self.analyzer.analyze(source, "sample.py")

    def test_vulnerable_sample_python_coverage(self):
        findings = self.analyze((SAMPLES / "vulnerable_sample.py").read_text(encoding="utf-8"))
        self.assertLessEqual(
            {
                "KISA-INPUT-01", "KISA-INPUT-02", "KISA-INPUT-03", "KISA-INPUT-05",
                "KISA-SEC-04", "KISA-SEC-06", "KISA-SEC-08", "KISA-SEC-11",
                "KISA-ERR-01", "KISA-CODE-05", "KISA-CAPS-02",
            },
            codes(findings),
        )
        self.assertNotIn("KISA-INPUT-04", codes(findings))
        for finding in findings:
            self.assertGreaterEqual(finding.column, 1)
            self.assertTrue(finding.evidence)

    def test_secure_sample_is_clean(self):
        self.assertEqual([], self.analyze((SAMPLES / "secure_sample.py").read_text(encoding="utf-8")))

    def test_each_class_minimal_snippet(self):
        cases = {
            "KISA-INPUT-01": "cursor.execute('SELECT * FROM t WHERE x=' + name)",
            "KISA-INPUT-02": "eval(user_input)",
            "KISA-INPUT-03": "base = '/tmp/'\nopen(base + user_path)",
            "KISA-INPUT-04": "mark_safe(user_html)",
            "KISA-INPUT-05": "import os\nos.system('ls ' + arg)",
            "KISA-SEC-06": "API_KEY = 'abcd1234efgh'",
            "KISA-SEC-04": "import hashlib\nhashlib.md5(data).hexdigest()",
            "KISA-SEC-08": "import random\nsession_token = random.randint(0, 9999)",
            "KISA-SEC-11": "# admin password = SuperSecret123 for staging\nx = 1",
            "KISA-CODE-05": "import pickle\npickle.loads(blob)",
            "KISA-CAPS-02": "app.run(debug=True)",
            "KISA-ERR-01": "try:\n    work()\nexcept Exception as e:\n    return HttpResponse(str(e))",
        }
        for code, snippet in cases.items():
            with self.subTest(code=code):
                self.assertIn(code, codes(self.analyze(snippet)))

    def test_secure_guards(self):
        self.assertNotIn("KISA-INPUT-01", codes(self.analyze("cursor.execute(q, (a, b))")))
        self.assertNotIn("KISA-INPUT-05", codes(self.analyze("import subprocess\nsubprocess.run(['ping', host])")))
        self.assertNotIn("KISA-INPUT-03", codes(self.analyze("import os\nopen(os.path.basename(name))")))
        self.assertNotIn("KISA-SEC-06", codes(self.analyze("import os\npassword = os.getenv('DB_PASSWORD')")))
        self.assertNotIn("KISA-SEC-04", codes(self.analyze("import hashlib\nhashlib.sha256(data).hexdigest()")))
        self.assertNotIn("KISA-SEC-08", codes(self.analyze("import random\njitter = random.random()")))
        self.assertNotIn("KISA-SEC-08", codes(self.analyze("import secrets\ntoken = secrets.token_hex(16)")))
        self.assertNotIn("KISA-CODE-05", codes(self.analyze("import yaml\nyaml.load(text, Loader=yaml.SafeLoader)")))
        self.assertNotIn("KISA-CAPS-02", codes(self.analyze("server.run(port=8000)")))
        self.assertNotIn("KISA-ERR-01", codes(self.analyze("try:\n    work()\nexcept Exception as e:\n    logging.exception(e)")))
        self.assertNotIn("KISA-SEC-11", codes(self.analyze("# normal comment about the algorithm\nx = 1")))


class TextAnalyzerTests(unittest.TestCase):
    def test_javascript_baseline(self):
        findings = JavaScriptAnalyzer().analyze((SAMPLES / "vulnerable_sample.js").read_text(encoding="utf-8"), "s.js")
        self.assertEqual(
            {
                "KISA-INPUT-01", "KISA-INPUT-02", "KISA-INPUT-03", "KISA-INPUT-04", "KISA-INPUT-05",
                "KISA-SEC-04", "KISA-SEC-06", "KISA-SEC-08", "KISA-SEC-11", "KISA-ERR-01", "KISA-CAPS-02",
            },
            codes(findings),
        )
        self.assertTrue(all(f.confidence == 0.5 for f in findings))

    def test_javascript_secure_is_clean(self):
        self.assertEqual([], JavaScriptAnalyzer().analyze((SAMPLES / "secure_sample.js").read_text(encoding="utf-8"), "s.js"))

    def test_java_baseline(self):
        findings = JavaAnalyzer().analyze((SAMPLES / "vulnerable_sample.java").read_text(encoding="utf-8"), "S.java")
        self.assertLessEqual(
            {
                "KISA-INPUT-01", "KISA-INPUT-03", "KISA-INPUT-04", "KISA-INPUT-05",
                "KISA-SEC-04", "KISA-SEC-06", "KISA-SEC-08", "KISA-SEC-11",
                "KISA-ERR-01", "KISA-CODE-05", "KISA-CAPS-02",
            },
            codes(findings),
        )
        self.assertTrue(all(f.confidence == 0.5 for f in findings))


class AnalyzeFileTests(unittest.TestCase):
    def _platform(self, rules):
        repos = Repositories()
        self.admin = User(new_id(), "admin", hash_password("secret"), Role.ADMIN)
        repos.add_user(self.admin)
        for rule in rules:
            repos.rules.add(rule, rule.rule_id)
        return Platform(repos, TokenService(b"secret"), AnalyzerRegistry())

    def _run(self, platform, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.py"
            path.write_text(source, encoding="utf-8")
            project = platform.create_project(self.admin, {
                "name": "demo", "source_type": "PATH", "target_language": "PYTHON",
                "source_location": str(path),
            })
            return platform.analyze_file(self.admin, project.project_id)

    def test_records_findings_for_rules_without_a_catalog_row(self):
        platform = self._platform([Rule(new_id(), "KISA-INPUT-01", "SQL", "", "INPUT", 1, None, "HIGH")])
        run = self._run(platform, 'PASSWORD = "secret"\nresult = eval(user_input)\n')
        self.assertEqual("COMPLETED", run.status.value)
        self.assertEqual(2, run.summary["finding_count"])
        self.assertEqual({"HIGH": 2}, run.summary["severity"])

    def test_inactive_catalog_row_suppresses_its_findings(self):
        rule = Rule(new_id(), "KISA-INPUT-02", "코드 삽입", "", "INPUT", 2, None, "HIGH", is_active=False)
        platform = self._platform([rule])
        run = self._run(platform, "result = eval(user_input)\n")
        self.assertEqual(0, run.summary["finding_count"])

    def test_project_files_lists_workspace_relative_paths(self):
        platform = self._platform([])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pkg").mkdir()
            (root / "pkg" / "a.py").write_text("x = 1\n", encoding="utf-8")
            (root / "b.js").write_text("var x = 1;\n", encoding="utf-8")
            project = platform.create_project(self.admin, {
                "name": "tree", "source_type": "PATH", "target_language": "AUTO",
                "source_location": str(root),
            })
            listing = platform.project_files(self.admin, project.project_id)
        paths = sorted(item["path"] for item in listing)
        self.assertEqual(["b.js", "pkg/a.py"], paths)
        self.assertNotIn("..", "".join(paths))


if __name__ == "__main__":
    unittest.main()
