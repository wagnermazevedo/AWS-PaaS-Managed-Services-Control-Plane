"""Modo gravação (lib/mask.py): o que vai para a tela sai mascarado; YAML e JSON ficam reais."""

import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import ACCOUNT, PROD_ROLE, World  # noqa: E402
from test_control_plane import Runner  # noqa: E402


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class Masking(unittest.TestCase):
    def test_console_summary_and_csv_hide_ids_but_keep_lab_names(self):
        runner = Runner(World())
        path, _ = runner.scan()
        folder = os.path.dirname(path)
        for human in ("summary.md", "paas_scan_export.csv"):
            text = read(os.path.join(folder, human))
            self.assertNotIn(ACCOUNT, text, human)
            self.assertIn("ps-lab-droid-factory", text, human)
        self.assertIn("ps-lab-droid-factory", runner.console)
        self.assertNotIn(ACCOUNT, runner.console)

    def test_names_outside_the_lab_are_masked_with_mode_all(self):
        import tempfile
        from lib.io import load_yaml, write_yaml
        from test_control_plane import rules_with
        tmp = tempfile.mkdtemp()
        rules = rules_with(tmp)
        doc = load_yaml(rules)
        doc["targets"] = {"mode": "all"}
        write_yaml(rules, doc)
        runner = Runner(World(), rules=rules)
        path, _ = runner.scan()
        self.assertNotIn(PROD_ROLE, read(os.path.join(os.path.dirname(path), "summary.md")))
        self.assertIn(PROD_ROLE, read(path))

    def test_yaml_keeps_real_values(self):
        path, scan = Runner(World()).scan()
        self.assertEqual(scan["metadata"]["callerAccountId"], ACCOUNT)

    def test_no_mask_flag_turns_it_off(self):
        runner = Runner(World())
        runner.extra = ["--no-mask"]
        path, _ = runner.scan()
        self.assertIn(ACCOUNT, read(os.path.join(os.path.dirname(path), "summary.md")))


if __name__ == "__main__":
    unittest.main()
