"""Inventário de PaaS e serviços gerenciados (somente APIs de leitura).

Cada tipo de recurso tem duas funções:
  list_<tipo>(clients, region)       -> todos os recursos da região, com as tags
  load_<tipo>(clients, locator, ...) -> um recurso pelo locator, ao vivo (usado pelo remediate)

O locator é o NOME do recurso (projeto do CodeBuild, notebook, banco, role), que não leva
o número da conta: o test-control-plane.sh anonimiza números de conta no YAML.

Os quatro "droides" do episódio:
  codebuild    projetos do AWS CodeBuild
  notebook     notebooks do Amazon SageMaker
  rds          instâncias do Amazon RDS
  servicerole  roles do IAM que um serviço da AWS assume (Principal.Service na trust policy)
"""

import json
from typing import Any, Dict, List
from urllib.parse import unquote

from botocore.exceptions import ClientError


class NotFound(Exception):
    pass


def _code(err: ClientError) -> str:
    return err.response.get("Error", {}).get("Code", "")


def _paginate(c, operation: str, key: str, **kwargs) -> List[Any]:
    items: List[Any] = []
    for page in c.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(key, []) or [])
    return items


def _tags(raw, key="Key", value="Value") -> Dict[str, str]:
    return {t[key]: t.get(value, "") for t in raw or []}


def _doc(raw) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    return json.loads(unquote(raw)) if raw else {}


# ---- CodeBuild -----------------------------------------------------------------------

def _project(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"locator": p["name"], "name": p["name"], "meta": p, "tags": _tags(p.get("tags"), "key", "value")}


def list_projects(clients, region: str) -> List[Dict[str, Any]]:
    cb = clients["codebuild"]
    names = _paginate(cb, "list_projects", "projects")
    out = []
    for i in range(0, len(names), 100):   # batch_get_projects aceita até 100 nomes
        out.extend(_project(p) for p in cb.batch_get_projects(names=names[i:i + 100]).get("projects", []))
    return out


def load_project(clients, locator: str, region: str) -> Dict[str, Any]:
    found = clients["codebuild"].batch_get_projects(names=[locator]).get("projects", [])
    if not found:
        raise NotFound(locator)
    return _project(found[0])


# ---- SageMaker notebooks ----------------------------------------------------------------

def _notebook(sm, name: str) -> Dict[str, Any]:
    try:
        meta = sm.describe_notebook_instance(NotebookInstanceName=name)
    except ClientError as err:
        if _code(err) == "ValidationException":
            raise NotFound(name)
        raise
    tags = _tags(_paginate(sm, "list_tags", "Tags", ResourceArn=meta["NotebookInstanceArn"]))
    return {"locator": name, "name": name, "meta": meta, "tags": tags}


def list_notebooks(clients, region: str) -> List[Dict[str, Any]]:
    sm = clients["sagemaker"]
    return [_notebook(sm, n["NotebookInstanceName"]) for n in _paginate(sm, "list_notebook_instances", "NotebookInstances")
            if n.get("NotebookInstanceStatus") not in ("Deleting",)]


def load_notebook(clients, locator: str, region: str) -> Dict[str, Any]:
    return _notebook(clients["sagemaker"], locator)


# ---- RDS -----------------------------------------------------------------------------------

def _db(d: Dict[str, Any]) -> Dict[str, Any]:
    return {"locator": d["DBInstanceIdentifier"], "name": d["DBInstanceIdentifier"], "meta": d, "tags": _tags(d.get("TagList"))}


def list_dbs(clients, region: str) -> List[Dict[str, Any]]:
    return [_db(d) for d in _paginate(clients["rds"], "describe_db_instances", "DBInstances")
            if d.get("DBInstanceStatus") not in ("deleting",)]


def load_db(clients, locator: str, region: str) -> Dict[str, Any]:
    try:
        found = clients["rds"].describe_db_instances(DBInstanceIdentifier=locator).get("DBInstances", [])
    except ClientError as err:
        if _code(err) == "DBInstanceNotFound":
            raise NotFound(locator)
        raise
    if not found:
        raise NotFound(locator)
    return _db(found[0])


# ---- Service roles ---------------------------------------------------------------------------
# Só as roles cuja trust policy deixa um serviço da AWS assumir. Service-linked roles
# (/aws-service-role/) e as do Identity Center (/aws-reserved/) são da AWS: nem entram.

SKIP_PATHS = ("/aws-service-role/", "/aws-reserved/")


def service_principals(trust: Dict[str, Any]) -> List[str]:
    out = []
    stmts = trust.get("Statement") or []
    for s in [stmts] if isinstance(stmts, dict) else stmts:
        if s.get("Effect") != "Allow":
            continue
        svc = (s.get("Principal") or {}).get("Service") if isinstance(s.get("Principal"), dict) else None
        out.extend([svc] if isinstance(svc, str) else list(svc or []))
    return sorted(set(out))


def _role(iam, r: Dict[str, Any]) -> Dict[str, Any]:
    tags = _tags(_paginate(iam, "list_role_tags", "Tags", RoleName=r["RoleName"]))
    trust = _doc(r.get("AssumeRolePolicyDocument"))
    return {"locator": r["RoleName"], "name": r["RoleName"], "tags": tags,
            "meta": {"Arn": r["Arn"], "Path": r.get("Path", "/"), "Trust": trust, "Services": service_principals(trust)}}


def list_service_roles(clients, region: str) -> List[Dict[str, Any]]:
    iam = clients["iam"]
    out = []
    for r in _paginate(iam, "list_roles", "Roles"):
        if r.get("Path", "/").startswith(SKIP_PATHS):
            continue
        if not service_principals(_doc(r.get("AssumeRolePolicyDocument"))):
            continue
        out.append(_role(iam, r))
    return out


def load_service_role(clients, locator: str, region: str) -> Dict[str, Any]:
    iam = clients["iam"]
    try:
        role = iam.get_role(RoleName=locator)["Role"]
    except ClientError as err:
        if _code(err) == "NoSuchEntity":
            raise NotFound(locator)
        raise
    return _role(iam, role)


KINDS = {
    "codebuild": {"type": "AWS::CodeBuild::Project", "list": list_projects, "load": load_project},
    "notebook": {"type": "AWS::SageMaker::NotebookInstance", "list": list_notebooks, "load": load_notebook},
    "rds": {"type": "AWS::RDS::DBInstance", "list": list_dbs, "load": load_db},
    "servicerole": {"type": "AWS::IAM::Role", "list": list_service_roles, "load": load_service_role},
}
