import tempfile
import unittest
from pathlib import Path

from anti_qsignature.config import load_project_config


class ProjectConfigTests(unittest.TestCase):
    def test_loads_team_scan_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".antiq.toml"
            path.write_text(
                """
[scan]
exclude = ["vendor/**"]
ignore_rules = ["AQ005"]
fail_on = "medium"
fuzz_cases = 2048
qsharp = "required"
external_tools = true
""".strip(),
                encoding="utf-8",
            )
            config = load_project_config(path)
            self.assertEqual(config.exclude, ["vendor/**"])
            self.assertEqual(config.ignore_rules, ["AQ005"])
            self.assertEqual(config.fail_on, "medium")
            self.assertEqual(config.fuzz_cases, 2048)
            self.assertEqual(config.qsharp, "required")
            self.assertTrue(config.external_tools)


if __name__ == "__main__":
    unittest.main()
