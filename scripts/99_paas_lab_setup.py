#!/usr/bin/env python3
"""[99] LAB SETUP: cria os droides mal configurados que os scripts 00, 01 e 02 vão testar. Use SOMENTE numa conta de testes.

Sobe o lab_insecure/paas-lab.yaml (stack ps-control-plane-lab), tudo com a tag ps-lab=true e custo zero:
  - projeto ps-lab-droid-factory: modo privilegiado, DB_PASSWORD em texto puro e sem logs (PS.1, PS.2 e PS.3);
  - projeto ps-lab-bb8: conforme;
  - projeto ps-lab-k2so: privilegiado, com ps-exception e exception-owner=platform-team (vira EXCEPTION);
  - role ps-lab-r2d2: service role do CodeBuild com AdministratorAccess e sem aws:SourceAccount (PS.6 e PS.7);
  - role ps-lab-c3po: service role mínima, com aws:SourceAccount.
As duas roles têm o boundary ps-lab-boundary: mesmo "admin", só escrevem log de build e leem os parâmetros do módulo.
Notebook do SageMaker (PS.4) e RDS (PS.5) cobram por hora e ficam só nos testes offline.

  python3 ~/AWS-PaaS-Managed-Services-Control-Plane/scripts/99_paas_lab_setup.py --region us-east-1             # cria
  python3 ~/AWS-PaaS-Managed-Services-Control-Plane/scripts/99_paas_lab_setup.py --region us-east-1 --list      # só mostra
  python3 ~/AWS-PaaS-Managed-Services-Control-Plane/scripts/99_paas_lab_setup.py --region us-east-1 --destroy   # desfaz tudo

O --destroy tira a política inline do módulo das roles do lab, apaga a stack, e apaga os parâmetros
/ps-control-plane/… e os grupos de log /aws/codebuild/ps-lab-… que o remediate criou (só os com a tag ManagedBy).
"""

import argparse

import _bootstrap  # noqa: F401
from botocore.exceptions import ClientError

from lib import mask
from lib.aws import client, session
from lib.io import repo_path
from lib.scope import LAB_PREFIXES
from scanner.checks import MANAGED_TAG_KEY, MANAGED_TAG_VALUE, MODULE_INLINE_POLICY, PARAM_PREFIX

STACK = "ps-control-plane-lab"
TEMPLATE = repo_path("lab_insecure", "paas-lab.yaml")
LAB_ROLES = ("ps-lab-r2d2", "ps-lab-c3po")
LAB_PROJECTS = ("ps-lab-droid-factory", "ps-lab-bb8", "ps-lab-k2so")
LOG_PREFIX = "/aws/codebuild/ps-lab-"


def _code(err):
    return err.response.get("Error", {}).get("Code", "")


def describe_stack(cfn):
    try:
        return cfn.describe_stacks(StackName=STACK)["Stacks"][0]
    except ClientError as err:
        if "does not exist" in str(err):
            return None
        raise


def create(c):
    with open(TEMPLATE, "r", encoding="utf-8") as f:
        body = f.read()
    try:
        c["cloudformation"].create_stack(StackName=STACK, TemplateBody=body, Capabilities=["CAPABILITY_NAMED_IAM"],
                                         Tags=[{"Key": "ps-lab", "Value": "true"}, {"Key": "Environment", "Value": "lab"}])
        c["cloudformation"].get_waiter("stack_create_complete").wait(StackName=STACK)
        print(f"[OK] Stack {STACK} criada")
    except ClientError as err:
        if _code(err) != "AlreadyExistsException":
            raise
        print(f"[OK] Stack {STACK} já existia")
    print("\nPróximo passo:")
    print(f"  python3 ~/AWS-PaaS-Managed-Services-Control-Plane/scripts/00_paas_scan.py --region {c['region']}")


def delete_module_inline_policies(iam):
    for role in LAB_ROLES:
        try:
            iam.delete_role_policy(RoleName=role, PolicyName=MODULE_INLINE_POLICY)
            print(f"[OK] Política inline {MODULE_INLINE_POLICY} tirada da role {role}")
        except ClientError as err:
            if _code(err) != "NoSuchEntity":
                raise


def delete_module_parameters(ssm):
    names = []
    for page in ssm.get_paginator("get_parameters_by_path").paginate(Path=PARAM_PREFIX, Recursive=True):
        names += [p["Name"] for p in page.get("Parameters", [])]
    mine = []
    for name in names:
        tags = {t["Key"]: t["Value"] for t in ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name).get("TagList", [])}
        if tags.get(MANAGED_TAG_KEY) == MANAGED_TAG_VALUE:
            mine.append(name)
        else:
            print(f"[WARN] O parâmetro {name} não tem a tag {MANAGED_TAG_KEY}; ficou")
    for i in range(0, len(mine), 10):
        ssm.delete_parameters(Names=mine[i:i + 10])
    if mine:
        print(f"[OK] {len(mine)} parâmetro(s) do módulo apagado(s) em {PARAM_PREFIX}/")


def delete_module_log_groups(logs):
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=LOG_PREFIX):
        for group in page.get("logGroups", []):
            arn = group.get("logGroupArn") or group["arn"].rstrip("*").rstrip(":")
            tags = logs.list_tags_for_resource(resourceArn=arn).get("tags", {})
            if tags.get(MANAGED_TAG_KEY) != MANAGED_TAG_VALUE:
                print(f"[WARN] O grupo {group['logGroupName']} não tem a tag {MANAGED_TAG_KEY}; ficou")
                continue
            logs.delete_log_group(logGroupName=group["logGroupName"])
            print(f"[OK] Grupo de log {group['logGroupName']} apagado")


def destroy(c):
    delete_module_inline_policies(c["iam"])
    if describe_stack(c["cloudformation"]):
        c["cloudformation"].delete_stack(StackName=STACK)
        c["cloudformation"].get_waiter("stack_delete_complete").wait(StackName=STACK)
        print(f"[OK] Stack {STACK} apagada")
    else:
        print(f"[OK] Stack {STACK} não existia")
    delete_module_parameters(c["ssm"])
    delete_module_log_groups(c["logs"])


def show(c):
    stack = describe_stack(c["cloudformation"])
    print(f"Stack {STACK}: {stack['StackStatus'] if stack else 'não existe'}")
    if not stack:
        return
    for p in c["codebuild"].batch_get_projects(names=list(LAB_PROJECTS)).get("projects", []):
        env = p.get("environment") or {}
        plain = [v["name"] for v in env.get("environmentVariables") or [] if (v.get("type") or "PLAINTEXT") == "PLAINTEXT"]
        logs = ((p.get("logsConfig") or {}).get("cloudWatchLogs") or {}).get("status", "ENABLED")
        print(f"  {p['name']:<22} privilegiado={env.get('privilegedMode', False)!s:<5} logs={logs:<8} texto puro={plain}")


def main():
    mask.setup(keep_prefixes=LAB_PREFIXES)
    parser = argparse.ArgumentParser(description="Laboratório do AWS PaaS & Managed Services Control Plane (conta de testes)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--destroy", action="store_true", help="Desfaz tudo o que o laboratório e o remediate criaram")
    group.add_argument("--list", action="store_true", help="Só mostra o estado, não altera nada")
    parser.add_argument("--yes", action="store_true", help="Não pede a confirmação LAB (para automação)")
    args = parser.parse_args()

    sess = session(args.profile, args.region)
    c = {svc: client(sess, svc) for svc in ("cloudformation", "codebuild", "iam", "ssm", "logs")}
    c["region"] = args.region
    if args.list:
        show(c)
    elif args.destroy:
        destroy(c)
    else:
        if not args.yes:
            print("Isto cria projetos do CodeBuild e service roles INSEGUROS de propósito (admin, senha em texto puro).")
            if input("Digite LAB para confirmar que esta é uma conta de testes: ").strip() != "LAB":
                raise SystemExit("[CANCELADO] Nada foi criado.")
        create(c)


if __name__ == "__main__":
    main()
