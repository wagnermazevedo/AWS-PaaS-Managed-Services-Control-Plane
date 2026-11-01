"""PS.7: ensina o droide de protocolo a perguntar de onde vem a ordem.

Acrescenta `aws:SourceAccount = <esta conta>` aos statements da trust policy que deixam um
serviço da lista assumir a role sem aws:SourceAccount, aws:SourceArn ou aws:SourceOrgID.
Quem usa a role nesta conta continua usando; um recurso de outra conta, não.
A trust policy anterior fica em `changes`, para desfazer com update-assume-role-policy.
"""

import json

from scanner.checks import DEFAULT_DEPUTY_SERVICES, deputy_gaps, statements


def run(clients, res, params, ctx, dry_run):
    services = params.get("services") or DEFAULT_DEPUTY_SERVICES
    before = res["meta"]["Trust"]
    gaps = {str(g["statement"]) for g in deputy_gaps(before, services)}
    doc = json.loads(json.dumps(before))
    stmts = statements(doc)
    for idx, s in enumerate(stmts):
        if str(s.get("Sid") or idx) in gaps:
            cond = s.setdefault("Condition", {})
            cond.setdefault("StringEquals", {})["aws:SourceAccount"] = ctx["account"]
    doc["Statement"] = stmts
    if dry_run:
        return {"ok": True, "message": f"DRY_RUN: exigiria aws:SourceAccount na trust policy de {res['name']}", "changes": []}
    clients["iam"].update_assume_role_policy(RoleName=res["locator"], PolicyDocument=json.dumps(doc))
    return {"ok": True, "message": f"APPLIED: trust policy de {res['name']} só aceita o serviço vindo desta conta",
            "changes": [{"trustPolicy": {"before": before}}]}
