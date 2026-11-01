"""PS.2: tira a senha do bolso do droide.

Para cada variável PLAINTEXT que parece segredo:
  1. grava o valor como SecureString em /ps-control-plane/<projeto>/<VARIAVEL> (tag ManagedBy);
  2. dá à service role do projeto ssm:GetParameters só nesse caminho (política inline do módulo);
  3. troca a variável para o tipo PARAMETER_STORE, apontando para o parâmetro.

O valor nunca vai para a tela, para o plano nem para o resultado: só o nome da variável e do parâmetro.
Para desfazer, o valor continua no parâmetro: `aws ssm get-parameter --with-decryption`.
"""

from botocore.exceptions import ClientError

from remediate._role_access import grant, role_in_scope, role_name, sid_for
from scanner.checks import DEFAULT_SECRET_NAMES, MANAGED_TAG_KEY, MANAGED_TAG_VALUE, PARAM_PREFIX, plaintext_secrets

TAGS = [{"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE}]


def _put(ssm, name, value):
    try:
        ssm.put_parameter(Name=name, Value=value, Type="SecureString", Tags=TAGS,
                          Description="Criado pelo AWS PaaS & Managed Services Control Plane (PS.2)")
        return None
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ParameterAlreadyExists":
            raise
    tags = {t["Key"]: t["Value"] for t in ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name).get("TagList", [])}
    if tags.get(MANAGED_TAG_KEY) != MANAGED_TAG_VALUE:
        return f"REFUSED: o parâmetro {name} já existe e não é do módulo (sem a tag {MANAGED_TAG_KEY}); nada foi alterado"
    ssm.put_parameter(Name=name, Value=value, Type="SecureString", Overwrite=True)
    return None


def run(clients, res, params, ctx, dry_run):
    project = res["meta"]
    names = plaintext_secrets(project, params.get("name_patterns") or DEFAULT_SECRET_NAMES)
    role = role_name(project.get("serviceRole"))
    if not role_in_scope(clients, role, ctx):
        return {"ok": False, "changes": [],
                "message": f"REFUSED: a service role {role} não está no escopo; dê ssm:GetParameters em {PARAM_PREFIX}/{res['name']}/* "
                           "à role e mova as variáveis à mão. Nada foi alterado"}
    resource = f"arn:{ctx['partition']}:ssm:{ctx['region']}:{ctx['account']}:parameter{PARAM_PREFIX}/{res['name']}/*"
    if dry_run:
        return {"ok": True, "changes": [],
                "message": f"DRY_RUN: moveria {', '.join(names)} de {res['name']} para o Parameter Store (SecureString) "
                           f"e daria ssm:GetParameters à role {role}"}

    env = dict(project["environment"])
    variables = [dict(v) for v in env.get("environmentVariables") or []]
    changes = []
    for var in variables:
        if var.get("name") not in names:
            continue
        param = f"{PARAM_PREFIX}/{res['name']}/{var['name']}"
        refused = _put(clients["ssm"], param, var.get("value") or "")
        if refused:
            return {"ok": False, "message": refused, "changes": changes}
        var.update(type="PARAMETER_STORE", value=param)
        changes.append({"variable": var["name"], "parameter": param, "before": {"type": "PLAINTEXT"}})
    granted = grant(clients, role, sid_for("ReadParams", res["name"]), ["ssm:GetParameters"], resource, dry_run=False)
    if granted:
        changes.append(granted)
    env["environmentVariables"] = variables
    clients["codebuild"].update_project(name=res["name"], environment=env)
    return {"ok": True, "changes": changes,
            "message": f"APPLIED: {', '.join(names)} de {res['name']} agora vêm do Parameter Store (SecureString)"}
