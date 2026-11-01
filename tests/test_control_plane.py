"""Testes offline do ciclo scan -> plan -> remediate.

Rodar: python3 -m unittest discover -s tests -v
"""

import glob
import io
import json
import os
import runpy
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import (ACCOUNT, BB8, C3PO, CT_ROLE, DB, FACTORY, K2SO, LAMBDA_ROLE, NOTEBOOK, PROD_DB, PROD_NOTEBOOK,  # noqa: E402
                   PROD_PROJECT, PROD_ROLE, R2D2, SECRET_VALUE, World)
from lib.io import load_yaml, write_yaml  # noqa: E402
import maskstate  # noqa: E402

RULES = os.path.join(REPO, "config", "paas_map.yaml")


class Runner:
    def __init__(self, world, rules=RULES, env=None):
        self.world = world
        self.rules = rules
        self.env = env or {}
        self.extra = []
        self.tmp = tempfile.mkdtemp()
        self.console = ""

    def _run(self, script, *args):
        screen = io.StringIO()
        with maskstate.isolated(self.env), \
             mock.patch.object(sys, "stdout", screen), mock.patch.object(sys, "stderr", screen), \
             mock.patch("lib.aws.client", side_effect=self.world.client), \
             mock.patch("lib.aws.session", return_value=None), mock.patch("time.sleep"), \
             mock.patch.object(sys, "argv", [script, *args, *self.extra]):
            try:
                runpy.run_path(os.path.join(REPO, "scripts", script), run_name="__main__")
            except SystemExit as exc:
                return exc.code
            finally:
                self.console = screen.getvalue()
        return 0

    def _latest(self, pattern):
        return max(glob.glob(pattern), key=os.path.getmtime)

    def scan(self):
        out = os.path.join(self.tmp, "outputs")
        code = self._run("00_paas_scan.py", "--region", "us-east-1", "--output-dir", out, "--rules", self.rules)
        assert code == 0, (code, self.console)
        path = self._latest(os.path.join(out, "*", "paas_scan_export.yaml"))
        return path, load_yaml(path)

    def plan(self, scan_yaml):
        path = os.path.join(self.tmp, "remediation_plan.yaml")
        code = self._run("01_paas_plan.py", "--input-yaml", scan_yaml, "--rules", self.rules, "--output-yaml", path)
        assert code == 0, (code, self.console)
        return path, load_yaml(path)

    def remediate(self, plan_path, mode):
        out = os.path.join(self.tmp, "rem")
        code = self._run("02_paas_remediate.py", "--region", "us-east-1", "--yaml", plan_path, "--mode", mode, "--output-dir", out)
        with open(self._latest(os.path.join(out, "*", "paas_remediation_results.json")), encoding="utf-8") as f:
            return code, json.load(f)

    def cycle(self, mode="apply"):
        scan_path, _ = self.scan()
        plan_path, plan = self.plan(scan_path)
        code, results = self.remediate(plan_path, mode)
        return plan, code, results


def find(items, control, name=None):
    return [i for i in items if i["control"] == control
            and (name is None or name in ((i["resource"] or {}).get("name"), (i["resource"] or {}).get("id")))]


def one(items, control, name=None):
    found = find(items, control, name)
    assert len(found) == 1, (control, name, found)
    return found[0]


def rules_with(tmp, **overrides):
    """Cópia do mapa com parâmetros trocados, ex.: rules_with(tmp, **{"PS.7": {"services": ["lambda.amazonaws.com"]}})."""
    import shutil
    dst = os.path.join(tmp, "config")
    shutil.copytree(os.path.join(REPO, "config"), dst)
    for control, params in overrides.items():
        path = os.path.join(dst, "controls", f"{control}.yaml")
        doc = load_yaml(path)
        doc.setdefault("params", {}).update(params)
        write_yaml(path, doc)
    return os.path.join(dst, "paas_map.yaml")


PARAM = f"/ps-control-plane/{FACTORY}/DB_PASSWORD"


def env_var(world, project, name):
    return next(v for v in world.projects[project]["environment"]["environmentVariables"] if v["name"] == name)


class FullCycle(unittest.TestCase):
    def test_scan_flags_the_lab_and_is_read_only(self):
        world = World()
        _, scan = Runner(world).scan()
        items = scan["spec"]["items"]
        self.assertEqual(world.writes(), [])
        self.assertEqual(one(items, "PS.1", FACTORY)["status"], "FAIL")
        self.assertEqual(one(items, "PS.1", BB8)["status"], "PASS")
        self.assertEqual(one(items, "PS.2", FACTORY)["verified_state"]["plaintextSecrets"], ["DB_PASSWORD"])   # APP_ENV não conta
        self.assertEqual(one(items, "PS.3", FACTORY)["verified_state"]["reason"], "NO_BUILD_LOGS")
        self.assertEqual(one(items, "PS.3", BB8)["status"], "PASS")   # sem logsConfig, o CodeBuild usa o CloudWatch
        self.assertEqual(sorted(one(items, "PS.4", NOTEBOOK)["verified_state"]["gaps"]), ["DIRECT_INTERNET_ACCESS", "ROOT_ACCESS"])
        self.assertEqual(one(items, "PS.5", DB)["verified_state"]["reason"], "PUBLIC_DB")
        self.assertEqual(one(items, "PS.6", R2D2)["verified_state"]["adminVia"], ["AdministratorAccess"])
        self.assertEqual(one(items, "PS.6", C3PO)["status"], "PASS")
        self.assertEqual(one(items, "PS.7", R2D2)["verified_state"]["reason"], "CONFUSED_DEPUTY_RISK")
        self.assertEqual(one(items, "PS.7", C3PO)["status"], "PASS")
        self.assertEqual(one(items, "PS.7", LAMBDA_ROLE)["status"], "NOT_APPLICABLE")

    def test_secret_values_never_leave_the_account(self):
        world = World()
        runner = Runner(world)
        scan_path, _ = runner.scan()
        plan_path, _ = runner.plan(scan_path)
        runner.remediate(plan_path, "apply")
        for root, _, files in os.walk(runner.tmp):
            for f in files:
                with open(os.path.join(root, f), encoding="utf-8", errors="ignore") as fh:
                    self.assertNotIn(SECRET_VALUE, fh.read(), f)
        self.assertNotIn(SECRET_VALUE, runner.console)

    def test_production_and_aws_roles_are_out_of_scope(self):
        world = World()
        _, scan = Runner(world).scan()
        names = {(i["resource"] or {}).get("name") for i in scan["spec"]["items"]}
        for outside in (PROD_PROJECT, PROD_ROLE, PROD_NOTEBOOK, PROD_DB, CT_ROLE, "AWSServiceRoleForSupport"):
            self.assertNotIn(outside, names)
        scope = scan["metadata"]["scope"]
        self.assertEqual(scope["outOfScope"]["codebuild"], 1)
        self.assertEqual(scope["outOfScope"]["servicerole"], 1)   # prod; CT não é service role, e a service-linked nem entra
        self.assertFalse([p for s, n, p in world.calls if n == "list_role_tags" and p["RoleName"] == "AWSServiceRoleForSupport"])

    def test_plan_decisions(self):
        runner = Runner(World())
        _, plan = runner.plan(runner.scan()[0])
        items = plan["spec"]["items"]
        for control, name in (("PS.2", FACTORY), ("PS.3", FACTORY), ("PS.5", DB), ("PS.7", R2D2)):
            self.assertEqual(one(items, control, name)["decision"]["type"], "AUTO", control)
        for control, name in (("PS.1", FACTORY), ("PS.4", NOTEBOOK), ("PS.6", R2D2)):
            self.assertEqual(one(items, control, name)["decision"]["type"], "MANUAL", control)
        k2so = one(items, "PS.1", K2SO)
        self.assertEqual(k2so["decision"]["type"], "EXCEPTION")
        self.assertIn("platform-team", k2so["decision"]["reason"])

    def test_dry_run_changes_nothing(self):
        world = World()
        before = world.snapshot()
        _, code, results = Runner(world).cycle("dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(world.writes(), [])
        self.assertEqual(world.snapshot(), before)
        auto = [r for r in results["spec"]["results"] if r["decision"] == "AUTO"]
        self.assertTrue(auto and all(r["message"].startswith("DRY_RUN") for r in auto), auto)

    def test_apply_then_rescan_passes(self):
        world = World()
        runner = Runner(world)
        _, code, results = runner.cycle("apply")
        self.assertEqual(code, 0, results)
        auto = [r for r in results["spec"]["results"] if r["decision"] == "AUTO"]
        self.assertTrue(auto and all(r["ok"] and "VERIFIED" in r["message"] for r in auto), auto)
        # PS.2: o segredo foi para o Parameter Store e a variável aponta para ele
        self.assertEqual(world.parameters[PARAM]["type"], "SecureString")
        self.assertEqual(world.parameters[PARAM]["value"], SECRET_VALUE)
        self.assertEqual(world.parameters[PARAM]["tags"]["ManagedBy"], "aws-paas-managed-services-control-plane")
        self.assertEqual(env_var(world, FACTORY, "DB_PASSWORD"), {"name": "DB_PASSWORD", "value": PARAM, "type": "PARAMETER_STORE"})
        self.assertEqual(env_var(world, FACTORY, "APP_ENV")["type"], "PLAINTEXT")
        # A role do projeto ganhou só o necessário, na política inline do módulo
        stmts = {s["Sid"]: s for s in world.roles[C3PO]["inline"]["ps-control-plane-access"]["Statement"]}
        self.assertEqual(stmts["ReadParamsPsLabDroidFactory"]["Action"], ["ssm:GetParameters"])
        self.assertTrue(stmts["ReadParamsPsLabDroidFactory"]["Resource"].endswith(f"parameter/ps-control-plane/{FACTORY}/*"))
        self.assertIn("WriteLogsPsLabDroidFactory", stmts)
        # PS.3: logs ligados, com grupo e retenção
        self.assertEqual(world.projects[FACTORY]["logsConfig"]["cloudWatchLogs"]["status"], "ENABLED")
        self.assertEqual(world.log_groups[f"/aws/codebuild/{FACTORY}"]["retention"], 90)
        # PS.5 e PS.7
        self.assertFalse(world.dbs[DB]["PubliclyAccessible"])
        self.assertEqual(world.roles[R2D2]["trust"]["Statement"][0]["Condition"]["StringEquals"]["aws:SourceAccount"], ACCOUNT)
        # O que nunca muda: privilegiado, admin, notebook, produção, exceção
        self.assertTrue(world.projects[FACTORY]["environment"]["privilegedMode"])
        self.assertIn("arn:aws:iam::aws:policy/AdministratorAccess", world.roles[R2D2]["attached"])
        self.assertEqual(world.notebooks[NOTEBOOK]["RootAccess"], "Enabled")
        self.assertTrue(world.dbs[PROD_DB]["PubliclyAccessible"])
        self.assertEqual(world.projects[PROD_PROJECT]["environment"]["environmentVariables"][0]["type"], "PLAINTEXT")
        self.assertNotIn("Condition", world.roles[PROD_ROLE]["trust"]["Statement"][0])
        self.assertFalse([n for s, n, p in world.calls if n.startswith("delete_")])
        # Rescan e segunda rodada
        _, scan = runner.scan()
        for control, name in (("PS.2", FACTORY), ("PS.3", FACTORY), ("PS.5", DB), ("PS.7", R2D2)):
            self.assertEqual(one(scan["spec"]["items"], control, name)["status"], "PASS", control)
        _, code, again = runner.cycle("apply")
        self.assertEqual([r for r in again["spec"]["results"] if r["decision"] == "AUTO"], [])


class Guardrails(unittest.TestCase):
    def test_role_outside_scope_is_never_changed(self):
        world = World()
        del world.roles[C3PO]["tags"]["ps-lab"]
        _, code, results = Runner(world).cycle("apply")
        for control in ("PS.2", "PS.3"):
            r = one([dict(x, resource={"name": x["resource"]}) for x in results["spec"]["results"]], control, FACTORY)
            self.assertFalse(r["ok"])
            self.assertIn("REFUSED", r["message"])
        self.assertNotIn("ps-control-plane-access", world.roles[C3PO]["inline"])
        self.assertEqual(env_var(world, FACTORY, "DB_PASSWORD")["type"], "PLAINTEXT")
        self.assertEqual(world.parameters, {})

    def test_parameter_owned_by_someone_else_is_refused(self):
        world = World()
        world.parameters[PARAM] = {"value": "x", "type": "SecureString", "tags": {"team": "data"}}
        _, code, results = Runner(world).cycle("apply")
        r = one([dict(x, resource={"name": x["resource"]}) for x in results["spec"]["results"]], "PS.2", FACTORY)
        self.assertIn("REFUSED", r["message"])
        self.assertEqual(world.parameters[PARAM]["value"], "x")
        self.assertEqual(env_var(world, FACTORY, "DB_PASSWORD")["type"], "PLAINTEXT")

    def test_access_key_value_is_caught_even_with_innocent_name(self):
        world = World()
        world.projects[BB8]["environment"]["environmentVariables"] = [
            {"name": "MY_VAR", "value": "AKIA" + "ABCDEFGHIJKLMNOP", "type": "PLAINTEXT"}]
        _, scan = Runner(world).scan()
        self.assertEqual(one(scan["spec"]["items"], "PS.2", BB8)["verified_state"]["plaintextSecrets"], ["MY_VAR"])

    def test_control_tower_service_roles_are_report_only(self):
        world = World()
        world.roles["AWSControlTowerConfigRole"] = {"trust": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
            "tags": {"ps-lab": "true"}, "attached": [], "inline": {}, "path": "/"}
        runner = Runner(world)
        _, plan = runner.plan(runner.scan()[0])
        item = one(plan["spec"]["items"], "PS.7", "AWSControlTowerConfigRole")
        self.assertEqual(item["decision"]["type"], "MANUAL")
        self.assertIn("Control Tower", item["decision"]["reason"])

    def test_tag_removed_after_plan_is_refused(self):
        world = World()
        runner = Runner(world)
        plan_path, _ = runner.plan(runner.scan()[0])
        world.dbs[DB]["TagList"] = []
        _, results = runner.remediate(plan_path, "apply")
        r = one([dict(x, resource={"name": x["resource"]}) for x in results["spec"]["results"]], "PS.5", DB)
        self.assertIn("REFUSED", r["message"])
        self.assertTrue(world.dbs[DB]["PubliclyAccessible"])

    def test_plan_from_another_account_is_refused(self):
        runner = Runner(World())
        plan_path, plan = runner.plan(runner.scan()[0])
        plan["metadata"]["callerAccountId"] = "111122223333"
        write_yaml(plan_path, plan)
        code = runner._run("02_paas_remediate.py", "--region", "us-east-1", "--yaml", plan_path, "--mode", "apply")
        self.assertIn("outra conta", str(code))

    def test_custom_deputy_service_list(self):
        tmp = tempfile.mkdtemp()
        runner = Runner(World(), rules=rules_with(tmp, **{"PS.7": {"services": ["lambda.amazonaws.com"]}}))
        _, scan = runner.scan()
        self.assertEqual(one(scan["spec"]["items"], "PS.7", LAMBDA_ROLE)["status"], "FAIL")
        self.assertEqual(one(scan["spec"]["items"], "PS.7", R2D2)["status"], "NOT_APPLICABLE")


class MapAndCommands(unittest.TestCase):
    def test_repo_map_loads_every_control_file(self):
        from lib.rules import load_rules
        doc = load_rules(RULES)
        self.assertEqual(sorted(doc["controls"]), [f"PS.{n}" for n in range(1, 8)])
        self.assertEqual(doc["targets"], {"mode": "tagged", "tag": {"ps-lab": "true"}})
        from remediate import REGISTRY
        for cid, rule in doc["controls"].items():
            if rule["decision"] == "AUTO":
                self.assertIn(rule["action"], REGISTRY, cid)

    def test_new_control_without_check_is_reported(self):
        tmp = tempfile.mkdtemp()
        rules = rules_with(tmp)
        write_yaml(os.path.join(tmp, "config", "controls", "PS.8.yaml"),
                   {"id": "PS.8", "title": "Pipeline sem aprovação manual", "decision": "MANUAL", "reason": "desafio"})
        _, scan = Runner(World(), rules=rules).scan()
        self.assertEqual(one(scan["spec"]["items"], "PS.8")["verified_state"]["reason"], "NO_CHECK")

    def test_plan_without_input_uses_latest_scan(self):
        runner = Runner(World())
        scan_path, _ = runner.scan()
        out = os.path.dirname(os.path.dirname(scan_path))
        plan_path = os.path.join(runner.tmp, "p.yaml")
        self.assertEqual(runner._run("01_paas_plan.py", "--output-dir", out, "--rules", RULES, "--output-yaml", plan_path), 0)
        self.assertIn("scan mais recente", runner.console)

    def test_remediate_without_plan_explains(self):
        code = Runner(World())._run("02_paas_remediate.py", "--region", "us-east-1", "--yaml", "/nao/existe.yaml")
        self.assertIn("Rode o 00", str(code))


if __name__ == "__main__":
    unittest.main()
