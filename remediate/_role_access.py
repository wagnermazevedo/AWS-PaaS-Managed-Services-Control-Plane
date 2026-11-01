"""A permissão mínima que uma correção precisa dar à service role do projeto.

Exemplo: ao tirar a senha do bolso do droide (PS.2), o CodeBuild passa a ler o parâmetro
do Parameter Store. A service role precisa de ssm:GetParameters naquele caminho, e só nele.

As permissões ficam numa política inline só do módulo (ps-control-plane-access), um
statement por projeto e por motivo. A role precisa estar no escopo (tags dela): role de
fora do escopo não é alterada, e a correção vira REFUSED antes de mexer em qualquer coisa.
"""

import json
import re

from botocore.exceptions import ClientError

from lib.scope import in_scope
from scanner.checks import MODULE_INLINE_POLICY


def role_name(role_arn: str) -> str:
    return (role_arn or "").rsplit("/", 1)[-1]


def sid_for(*parts: str) -> str:
    words = [w for p in parts for w in re.split(r"[^A-Za-z0-9]+", p) if w]
    return "".join(w[:1].upper() + w[1:] for w in words)[:100]


def role_in_scope(clients, role: str, ctx) -> bool:
    try:
        tags = {t["Key"]: t["Value"] for t in clients["iam"].list_role_tags(RoleName=role).get("Tags", [])}
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return False
        raise
    return in_scope(tags, (ctx.get("guardrails") or {}).get("targets") or {})


def grant(clients, role: str, sid: str, actions, resource: str, dry_run: bool):
    """Garante o statement `sid` na política inline do módulo. Devolve o change (ou None, se já existia igual)."""
    iam = clients["iam"]
    try:
        doc = iam.get_role_policy(RoleName=role, PolicyName=MODULE_INLINE_POLICY)["PolicyDocument"]
        doc = json.loads(doc) if isinstance(doc, str) else doc
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
        doc = {"Version": "2012-10-17", "Statement": []}
    stmt = {"Sid": sid, "Effect": "Allow", "Action": sorted(actions), "Resource": resource}
    current = [s for s in doc.get("Statement") or [] if s.get("Sid") == sid]
    if current == [stmt]:
        return None
    doc["Statement"] = [s for s in doc.get("Statement") or [] if s.get("Sid") != sid] + [stmt]
    if not dry_run:
        iam.put_role_policy(RoleName=role, PolicyName=MODULE_INLINE_POLICY, PolicyDocument=json.dumps(doc))
    return {"role": role, "inlinePolicy": MODULE_INLINE_POLICY, "statement": stmt}
