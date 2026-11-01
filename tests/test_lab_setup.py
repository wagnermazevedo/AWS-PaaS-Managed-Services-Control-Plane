"""Testes offline do 99_paas_lab_setup.py: cria, mostra e desfaz sem conta AWS."""

import io
import os
import runpy
import sys
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import maskstate  # noqa: E402
import yaml  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402
from fakes import ACCOUNT, C3PO, FACTORY, R2D2, World  # noqa: E402
from recorder import Recorder  # noqa: E402
from test_control_plane import Runner  # noqa: E402


def not_found():
    return ClientError({"Error": {"Code": "ValidationError", "Message": "Stack with id x does not exist"}}, "DescribeStacks")


class Lab:
    def __init__(self, world, stack_exists=False):
        self.world = world
        self.cfn = Recorder("cloudformation",
                            responses={"describe_stacks": {"Stacks": [{"StackName": "ps-control-plane-lab", "StackStatus": "CREATE_COMPLETE",
                                                                       "CreationTime": "2026-11-01T00:00:00Z"}]}},
                            errors={} if stack_exists else {"describe_stacks": not_found()})
        self.console = ""

    def client(self, sess, service):
        return self.cfn if service == "cloudformation" else self.world.client(sess, service)

    def run(self, *args):
        screen = io.StringIO()
        with maskstate.isolated(), mock.patch.object(sys, "stdout", screen), mock.patch.object(sys, "stderr", screen), \
             mock.patch("lib.aws.client", side_effect=self.client), mock.patch("lib.aws.session", return_value=None), \
             mock.patch.object(sys, "argv", ["99_paas_lab_setup.py", "--region", "us-east-1", *args]):
            try:
                runpy.run_path(os.path.join(REPO, "scripts", "99_paas_lab_setup.py"), run_name="__main__")
            finally:
                self.console = screen.getvalue()


class LabSetup(unittest.TestCase):
    def test_template_is_tagged_safe_and_free(self):
        class Loader(yaml.SafeLoader):
            pass
        for tag in ("!Ref", "!Sub", "!GetAtt"):
            Loader.add_multi_constructor(tag, lambda loader, suffix, node: None)
            Loader.add_constructor(tag, lambda loader, node: None)
        with open(os.path.join(REPO, "lab_insecure", "paas-lab.yaml"), encoding="utf-8") as f:
            tpl = yaml.load(f, Loader=Loader)
        types = set()
        for name, res in tpl["Resources"].items():
            types.add(res["Type"])
            props = res.get("Properties") or {}
            if "Tags" in props:
                self.assertIn({"Key": "ps-lab", "Value": "true"}, props["Tags"], name)
            if res["Type"] == "AWS::IAM::Role":
                self.assertIn("PermissionsBoundary", props, name)   # o "admin" do lab não consegue nada de admin
        self.assertEqual(types, {"AWS::IAM::ManagedPolicy", "AWS::IAM::Role", "AWS::CodeBuild::Project"})   # nada que cobre por hora

    def test_create_uses_named_iam_capability(self):
        lab = Lab(World())
        lab.run("--yes")
        create = [p for s, n, p in lab.cfn.calls if n == "create_stack"][0]
        self.assertEqual(create["Capabilities"], ["CAPABILITY_NAMED_IAM"])
        self.assertIn({"Key": "ps-lab", "Value": "true"}, create["Tags"])

    def test_create_asks_for_confirmation(self):
        lab = Lab(World())
        with mock.patch("builtins.input", return_value="nao"), self.assertRaises(SystemExit):
            lab.run()
        self.assertFalse([n for s, n, p in lab.cfn.calls if n == "create_stack"])

    def test_destroy_cleans_what_the_module_created(self):
        world = World()
        Runner(world).cycle("apply")
        self.assertTrue(world.parameters and world.log_groups)
        self.assertIn("ps-control-plane-access", world.roles[C3PO]["inline"])
        lab = Lab(world, stack_exists=True)
        lab.run("--destroy")
        self.assertNotIn("ps-control-plane-access", world.roles[C3PO]["inline"])   # antes da stack, senão o delete da role falha
        self.assertIn("ps-lab-c3po-minimal", world.roles[C3PO]["inline"])          # a da stack é da stack
        self.assertEqual(world.parameters, {})
        self.assertEqual(world.log_groups, {})
        self.assertIn(("cloudformation", "delete_stack", {"StackName": "ps-control-plane-lab"}), lab.cfn.calls)
        order = [n for s, n, p in world.calls + lab.cfn.calls if n in ("delete_role_policy", "delete_stack")]
        self.assertEqual(order[0], "delete_role_policy")

    def test_destroy_keeps_what_is_not_from_the_module(self):
        world = World()
        world.parameters["/ps-control-plane/other/TOKEN"] = {"value": "x", "type": "SecureString", "tags": {}}
        world.log_groups[f"/aws/codebuild/{FACTORY}"] = {"tags": {}, "retention": None}
        lab = Lab(world, stack_exists=True)
        lab.run("--destroy")
        self.assertIn("/ps-control-plane/other/TOKEN", world.parameters)
        self.assertIn(f"/aws/codebuild/{FACTORY}", world.log_groups)
        self.assertIn("[WARN]", lab.console)

    def test_list_changes_nothing(self):
        world = World()
        lab = Lab(world, stack_exists=True)
        lab.run("--list")
        self.assertEqual(world.writes(), [])
        self.assertIn(FACTORY, lab.console)
        self.assertIn("DB_PASSWORD", lab.console)
        self.assertNotIn("lab-not-a-real-password", lab.console)
        self.assertNotIn(ACCOUNT, lab.console)
        self.assertTrue(R2D2)


if __name__ == "__main__":
    unittest.main()
