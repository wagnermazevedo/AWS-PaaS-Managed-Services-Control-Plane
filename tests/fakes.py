"""Conta AWS em memória para testes offline: CodeBuild, SageMaker, RDS, IAM, SSM, CloudWatch Logs e STS.

Cada chamada é validada contra o modelo oficial do botocore (nome da operação,
parâmetros obrigatórios e tipos), então um parâmetro errado no código quebra
o teste do mesmo jeito que quebraria na AWS.

World() monta o mesmo cenário do lab_insecure/paas-lab.yaml, mais o que o lab não cria
porque cobra por hora (um notebook do SageMaker e um RDS público), e recursos "de produção"
sem a tag ps-lab, que o módulo nunca pode tocar.
"""

import copy
import json

import botocore.session
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

ACCOUNT = "210987654321"
OTHER = "999988887777"
REGION = "us-east-1"
_BOTO = botocore.session.get_session()
_REAL = {}

LAB = {"ps-lab": "true", "Environment": "lab"}
FACTORY, BB8, K2SO, PROD_PROJECT = "ps-lab-droid-factory", "ps-lab-bb8", "ps-lab-k2so", "prod-release"
R2D2, C3PO, PROD_ROLE, CT_ROLE, LAMBDA_ROLE = "ps-lab-r2d2", "ps-lab-c3po", "prod-codebuild-role", "AWSControlTowerExecution", "ps-lab-lambda-exec"
NOTEBOOK, PROD_NOTEBOOK = "ps-lab-holocron", "prod-research"
DB, PROD_DB = "ps-lab-archives", "prod-orders"
SECRET_VALUE = "lab-not-a-real-password"
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _err(code, msg="fake"):
    return ClientError({"Error": {"Code": code, "Message": msg}}, "op")


def _tags(d):
    return [{"Key": k, "Value": v} for k, v in d.items()]


def _perm(port, cidr="0.0.0.0/0", proto="tcp"):
    return {"IpProtocol": proto, "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": [],
            "PrefixListIds": [], "UserIdGroupPairs": []}


class _Paginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, PaginationConfig=None, **kwargs):  # noqa: N803
        yield self.fn(**kwargs)


class FakeService:
    service = ""

    def __init__(self, world):
        self.world = world
        if self.service not in _REAL:
            _REAL[self.service] = _BOTO.create_client(self.service, region_name=REGION,
                                                      aws_access_key_id="x", aws_secret_access_key="x")
        self._real = _REAL[self.service]
        self._model = _BOTO.get_service_model(self.service)

    def _check(self, name, params):
        op = self._model.operation_model(self._real.meta.method_to_api_mapping[name])
        if op.input_shape is not None:
            validate_parameters(params, op.input_shape)
        elif params:
            raise AssertionError(f"{name} não aceita parâmetros")
        self.world.calls.append((self.service, name, params))

    def get_paginator(self, name):
        assert self._real.can_paginate(name), f"{name} não é paginável"
        return _Paginator(getattr(self, name))

    def __getattribute__(self, name):
        attr = object.__getattribute__(self, name)
        if name.startswith("_") or name in ("world", "service", "get_paginator") or not callable(attr):
            return attr
        real = object.__getattribute__(self, "_real")
        if name not in real.meta.method_to_api_mapping:
            raise AttributeError(f"{name} não existe no boto3")

        def wrapped(**kwargs):
            object.__getattribute__(self, "_check")(name, kwargs)
            return attr(**kwargs)
        return wrapped


WRITE_PREFIXES = ("create_", "put_", "attach_", "detach_", "delete_", "update_", "tag_", "untag_", "add_", "remove_",
                  "set_", "enable_", "disable_", "revoke_", "authorize_", "associate_", "replace_", "modify_")




def _role_arn(name):
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


class FakeCodeBuild(FakeService):
    service = "codebuild"

    def list_projects(self, **kw):
        return {"projects": list(self.world.projects)}

    def batch_get_projects(self, **kw):
        return {"projects": [copy.deepcopy(self.world.projects[n]) for n in kw["names"] if n in self.world.projects],
                "projectsNotFound": [n for n in kw["names"] if n not in self.world.projects]}

    def update_project(self, **kw):
        p = self.world.projects[kw["name"]]
        for key in ("environment", "logsConfig"):
            if key in kw:
                p[key] = copy.deepcopy(kw[key])
        return {"project": copy.deepcopy(p)}


class FakeSageMaker(FakeService):
    service = "sagemaker"

    def list_notebook_instances(self, **kw):
        return {"NotebookInstances": [{"NotebookInstanceName": n, "NotebookInstanceArn": v["NotebookInstanceArn"],
                                       "NotebookInstanceStatus": v["NotebookInstanceStatus"]} for n, v in self.world.notebooks.items()]}

    def describe_notebook_instance(self, **kw):
        if kw["NotebookInstanceName"] not in self.world.notebooks:
            raise _err("ValidationException", "RecordNotFound")
        return {k: v for k, v in self.world.notebooks[kw["NotebookInstanceName"]].items() if k != "tags"}

    def list_tags(self, **kw):
        nb = next(v for v in self.world.notebooks.values() if v["NotebookInstanceArn"] == kw["ResourceArn"])
        return {"Tags": [{"Key": k, "Value": v} for k, v in nb["tags"].items()]}


class FakeRDS(FakeService):
    service = "rds"

    def describe_db_instances(self, **kw):
        dbs = list(self.world.dbs.values())
        if kw.get("DBInstanceIdentifier"):
            dbs = [d for d in dbs if d["DBInstanceIdentifier"] == kw["DBInstanceIdentifier"]]
            if not dbs:
                raise _err("DBInstanceNotFound")
        return {"DBInstances": copy.deepcopy(dbs)}

    def modify_db_instance(self, **kw):
        db = self.world.dbs[kw["DBInstanceIdentifier"]]
        if "PubliclyAccessible" in kw:
            db["PubliclyAccessible"] = kw["PubliclyAccessible"]
        return {"DBInstance": copy.deepcopy(db)}


class FakeIAM(FakeService):
    service = "iam"

    def _role(self, name):
        if name not in self.world.roles:
            raise _err("NoSuchEntity", f"role {name}")
        return self.world.roles[name]

    def _summary(self, name):
        r = self.world.roles[name]
        return {"RoleName": name, "RoleId": "AROA" + name.upper().replace("-", "")[:16].ljust(16, "X"), "Arn": _role_arn(name),
                "Path": r["path"], "CreateDate": "2026-10-01T00:00:00Z", "AssumeRolePolicyDocument": json.dumps(r["trust"])}

    def list_roles(self, **kw):
        return {"Roles": [self._summary(n) for n in self.world.roles], "IsTruncated": False}

    def get_role(self, **kw):
        self._role(kw["RoleName"])
        return {"Role": self._summary(kw["RoleName"])}

    def list_role_tags(self, **kw):
        return {"Tags": [{"Key": k, "Value": v} for k, v in self._role(kw["RoleName"])["tags"].items()], "IsTruncated": False}

    def list_attached_role_policies(self, **kw):
        return {"AttachedPolicies": [{"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in self._role(kw["RoleName"])["attached"]],
                "IsTruncated": False}

    def list_role_policies(self, **kw):
        return {"PolicyNames": list(self._role(kw["RoleName"])["inline"]), "IsTruncated": False}

    def get_role_policy(self, **kw):
        inline = self._role(kw["RoleName"])["inline"]
        if kw["PolicyName"] not in inline:
            raise _err("NoSuchEntity", "inline")
        return {"RoleName": kw["RoleName"], "PolicyName": kw["PolicyName"], "PolicyDocument": json.dumps(inline[kw["PolicyName"]])}

    def put_role_policy(self, **kw):
        self._role(kw["RoleName"])["inline"][kw["PolicyName"]] = json.loads(kw["PolicyDocument"])
        return {}

    def delete_role_policy(self, **kw):
        inline = self._role(kw["RoleName"])["inline"]
        if kw["PolicyName"] not in inline:
            raise _err("NoSuchEntity", "inline")
        del inline[kw["PolicyName"]]
        return {}

    def get_policy(self, **kw):
        assert kw["PolicyArn"] in self.world.policies
        return {"Policy": {"PolicyName": kw["PolicyArn"].rsplit("/", 1)[-1], "Arn": kw["PolicyArn"], "DefaultVersionId": "v1"}}

    def get_policy_version(self, **kw):
        return {"PolicyVersion": {"Document": json.dumps(self.world.policies[kw["PolicyArn"]]), "VersionId": kw["VersionId"],
                                  "IsDefaultVersion": True}}

    def update_assume_role_policy(self, **kw):
        self._role(kw["RoleName"])["trust"] = json.loads(kw["PolicyDocument"])
        return {}


class FakeSSM(FakeService):
    service = "ssm"

    def put_parameter(self, **kw):
        name = kw["Name"]
        if name in self.world.parameters and not kw.get("Overwrite"):
            raise _err("ParameterAlreadyExists")
        old = self.world.parameters.get(name, {})
        self.world.parameters[name] = {"value": kw["Value"], "type": kw.get("Type"),
                                       "tags": {t["Key"]: t["Value"] for t in kw.get("Tags", [])} or old.get("tags", {})}
        return {"Version": 1}

    def list_tags_for_resource(self, **kw):
        return {"TagList": [{"Key": k, "Value": v} for k, v in self.world.parameters[kw["ResourceId"]]["tags"].items()]}

    def get_parameters_by_path(self, **kw):
        return {"Parameters": [{"Name": n, "Type": p["type"]} for n, p in self.world.parameters.items() if n.startswith(kw["Path"] + "/")]}

    def delete_parameters(self, **kw):
        for n in kw["Names"]:
            self.world.parameters.pop(n, None)
        return {"DeletedParameters": kw["Names"], "InvalidParameters": []}


class FakeLogs(FakeService):
    service = "logs"

    def create_log_group(self, **kw):
        if kw["logGroupName"] in self.world.log_groups:
            raise _err("ResourceAlreadyExistsException")
        self.world.log_groups[kw["logGroupName"]] = {"tags": dict(kw.get("tags") or {}), "retention": None}
        return {}

    def put_retention_policy(self, **kw):
        self.world.log_groups[kw["logGroupName"]]["retention"] = kw["retentionInDays"]
        return {}

    def describe_log_groups(self, **kw):
        prefix = kw.get("logGroupNamePrefix", "")
        return {"logGroups": [{"logGroupName": n, "arn": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{n}:*",
                               "logGroupArn": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{n}"}
                              for n in self.world.log_groups if n.startswith(prefix)]}

    def list_tags_for_resource(self, **kw):
        name = kw["resourceArn"].split(":log-group:", 1)[1]
        return {"tags": self.world.log_groups[name]["tags"]}

    def delete_log_group(self, **kw):
        del self.world.log_groups[kw["logGroupName"]]
        return {}


class FakeSTS(FakeService):
    service = "sts"

    def get_caller_identity(self, **kw):
        return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/someone", "UserId": "AIDAEXAMPLE"}


def _project(name, role, tags, privileged=False, variables=None, logs=None):
    p = {"name": name, "arn": f"arn:aws:codebuild:{REGION}:{ACCOUNT}:project/{name}", "serviceRole": _role_arn(role),
         "source": {"type": "NO_SOURCE", "buildspec": "version: 0.2"}, "artifacts": {"type": "NO_ARTIFACTS"},
         "environment": {"type": "LINUX_CONTAINER", "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                         "computeType": "BUILD_GENERAL1_SMALL", "privilegedMode": privileged,
                         "environmentVariables": variables or []},
         "tags": [{"key": k, "value": v} for k, v in tags.items()]}
    if logs is not None:
        p["logsConfig"] = logs
    return p


def _trust(service="codebuild.amazonaws.com", condition=None):
    stmt = {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
    if condition:
        stmt["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [stmt]}


def _role(trust, tags=None, attached=None, inline=None, path="/"):
    return {"trust": trust, "tags": dict(tags or {}), "attached": list(attached or []), "inline": dict(inline or {}), "path": path}


class World:
    def __init__(self):
        self.calls = []
        no_logs = {"cloudWatchLogs": {"status": "DISABLED"}, "s3Logs": {"status": "DISABLED"}}
        self.projects = {
            FACTORY: _project(FACTORY, C3PO, LAB, privileged=True, logs=no_logs,
                              variables=[{"name": "DB_PASSWORD", "value": SECRET_VALUE, "type": "PLAINTEXT"},
                                         {"name": "APP_ENV", "value": "lab", "type": "PLAINTEXT"}]),
            BB8: _project(BB8, R2D2, LAB),
            K2SO: _project(K2SO, C3PO, {**LAB, "ps-exception": "Constroi imagens Docker", "exception-owner": "platform-team"},
                           privileged=True),
            PROD_PROJECT: _project(PROD_PROJECT, PROD_ROLE, {}, privileged=True, logs=no_logs,
                                   variables=[{"name": "GITHUB_TOKEN", "value": "prod-secret", "type": "PLAINTEXT"}]),
        }
        self.roles = {
            R2D2: _role(_trust(), LAB, attached=[ADMIN]),
            C3PO: _role(_trust(condition={"StringEquals": {"aws:SourceAccount": ACCOUNT}}), LAB,
                        inline={"ps-lab-c3po-minimal": {"Version": "2012-10-17", "Statement": [
                            {"Effect": "Allow", "Action": ["logs:PutLogEvents"], "Resource": "*"}]}}),
            LAMBDA_ROLE: _role(_trust("lambda.amazonaws.com"), LAB),   # serviço fora da lista do PS.7
            PROD_ROLE: _role(_trust(), attached=[ADMIN]),
            CT_ROLE: _role({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"},
                                                                    "Action": "sts:AssumeRole"}]}, attached=[ADMIN]),
            "AWSServiceRoleForSupport": _role(_trust("support.amazonaws.com"), path="/aws-service-role/support.amazonaws.com/"),
        }
        self.policies = {}
        self.notebooks = {
            NOTEBOOK: {"NotebookInstanceName": NOTEBOOK, "NotebookInstanceArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:notebook-instance/{NOTEBOOK}",
                       "NotebookInstanceStatus": "Stopped", "DirectInternetAccess": "Enabled", "RootAccess": "Enabled", "tags": LAB},
            PROD_NOTEBOOK: {"NotebookInstanceName": PROD_NOTEBOOK,
                            "NotebookInstanceArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:notebook-instance/{PROD_NOTEBOOK}",
                            "NotebookInstanceStatus": "InService", "DirectInternetAccess": "Enabled", "RootAccess": "Enabled", "tags": {}},
        }
        self.dbs = {
            DB: {"DBInstanceIdentifier": DB, "Engine": "postgres", "DBInstanceStatus": "available", "PubliclyAccessible": True,
                 "TagList": [{"Key": k, "Value": v} for k, v in LAB.items()]},
            PROD_DB: {"DBInstanceIdentifier": PROD_DB, "Engine": "mysql", "DBInstanceStatus": "available", "PubliclyAccessible": True,
                      "TagList": []},
        }
        self.parameters = {}
        self.log_groups = {}

    def snapshot(self):
        return copy.deepcopy((self.projects, self.roles, self.notebooks, self.dbs, self.parameters, self.log_groups))

    def writes(self):
        return [(s, n, p) for s, n, p in self.calls if n.startswith(WRITE_PREFIXES)]

    def client(self, sess, service):
        return {"codebuild": FakeCodeBuild, "sagemaker": FakeSageMaker, "rds": FakeRDS, "iam": FakeIAM, "ssm": FakeSSM,
                "logs": FakeLogs, "sts": FakeSTS}[service](self)
