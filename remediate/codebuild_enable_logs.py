"""PS.3: liga os logs de build no CloudWatch Logs.

Cria o grupo /aws/codebuild/<projeto> com retenção (tag ManagedBy), dá à service role
logs:CreateLogStream e logs:PutLogEvents só nesse grupo, e liga o cloudWatchLogs do projeto.
Os logs no S3, se existirem, ficam como estão.
"""

from botocore.exceptions import ClientError

from remediate._role_access import grant, role_in_scope, role_name, sid_for
from scanner.checks import MANAGED_TAG_KEY, MANAGED_TAG_VALUE


def run(clients, res, params, ctx, dry_run):
    project = res["meta"]
    group = f"/aws/codebuild/{res['name']}"
    retention = int(params.get("retention_days", 90))
    role = role_name(project.get("serviceRole"))
    if not role_in_scope(clients, role, ctx):
        return {"ok": False, "changes": [],
                "message": f"REFUSED: a service role {role} não está no escopo; dê logs:CreateLogStream e logs:PutLogEvents "
                           f"em {group} à role e ligue os logs à mão. Nada foi alterado"}
    if dry_run:
        return {"ok": True, "changes": [],
                "message": f"DRY_RUN: criaria o grupo {group} ({retention} dias), daria permissão de escrita à role {role} "
                           f"e ligaria os logs de {res['name']}"}
    changes = []
    logs = clients["logs"]
    try:
        logs.create_log_group(logGroupName=group, tags={MANAGED_TAG_KEY: MANAGED_TAG_VALUE})
        changes.append({"logGroup": group, "created": True})
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            raise
    logs.put_retention_policy(logGroupName=group, retentionInDays=retention)
    resource = f"arn:{ctx['partition']}:logs:{ctx['region']}:{ctx['account']}:log-group:{group}:*"
    granted = grant(clients, role, sid_for("WriteLogs", res["name"]), ["logs:CreateLogStream", "logs:PutLogEvents"], resource, dry_run=False)
    if granted:
        changes.append(granted)
    before = project.get("logsConfig") or {}
    clients["codebuild"].update_project(name=res["name"], logsConfig={
        "cloudWatchLogs": {"status": "ENABLED", "groupName": group},
        "s3Logs": before.get("s3Logs") or {"status": "DISABLED"}})
    changes.append({"logsConfig": {"before": before}})
    return {"ok": True, "changes": changes, "message": f"APPLIED: logs de {res['name']} no grupo {group}"}
