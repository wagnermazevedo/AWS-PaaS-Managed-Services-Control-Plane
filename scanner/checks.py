"""Avaliação dos controles de PaaS e serviços gerenciados (PS.1 a PS.7).

Cada verificador recebe (clients, resource, ctx) e devolve (status, verified_state).
Os mesmos verificadores são usados pelo scan e pelo remediate, que confere o
estado ao vivo antes e depois de cada mudança.

As três perguntas do episódio ("estes não são os droides que você procura"):
  Com qual role o serviço roda, e ela é maior do que precisa?   PS.6 (admin) e PS.7 (confused deputy)
  O que o droide carrega no bolso?                              PS.1 (modo privilegiado), PS.2 (segredo em texto) e PS.3 (sem logs)
  O serviço está exposto?                                       PS.4 (notebook com root e internet) e PS.5 (RDS público)

Regra de ouro: nenhum valor de variável de ambiente vai para o scan, o plan ou a tela. Só o nome.

Controle novo? Escreva o verificador aqui e registre em CHECKS com o tipo de
recurso (codebuild, notebook, rds ou servicerole).
"""

import fnmatch
import json
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote

from botocore.exceptions import ClientError

from lib.scope import PROTECTED_ROLE_PREFIXES, exception_of, in_scope
from scanner.inventory import KINDS, _paginate

PASS, FAIL, ERROR, NOT_APPLICABLE = "PASS", "FAIL", "ERROR", "NOT_APPLICABLE"

# Tudo que o próprio módulo cria (parâmetros no Parameter Store, a política inline nas service roles) leva esta tag
# ou este nome. O remediate só reaproveita, e o 99 --destroy só apaga, o que for do módulo.
MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "aws-paas-managed-services-control-plane"
MODULE_INLINE_POLICY = "ps-control-plane-access"
PARAM_PREFIX = "/ps-control-plane"
DEFAULT_SECRET_NAMES = ["*PASSWORD*", "*PASSWD*", "*SECRET*", "*TOKEN*", "*API_KEY*", "*APIKEY*", "*ACCESS_KEY*", "*PRIVATE_KEY*"]
# Cara de chave de acesso da AWS, mesmo com nome inocente (ex.: MY_VAR=AKIA...).
AWS_KEY_VALUE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
DEFAULT_DEPUTY_SERVICES = ["codebuild.amazonaws.com", "sagemaker.amazonaws.com", "codepipeline.amazonaws.com",
                           "codedeploy.amazonaws.com", "glue.amazonaws.com", "states.amazonaws.com", "events.amazonaws.com",
                           "scheduler.amazonaws.com", "config.amazonaws.com", "cloudformation.amazonaws.com"]
DEPUTY_CONDITION_KEYS = ("aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid", "aws:sourceorgpaths")
ADMIN_POLICY = "AdministratorAccess"
GROUP_KINDS: Dict[str, Tuple[str, ...]] = {}

Result = Tuple[str, Dict[str, Any]]


def _code(err: ClientError) -> str:
    return err.response.get("Error", {}).get("Code", "")


def _error_detail(err: Exception) -> str:
    if isinstance(err, ClientError):
        return f"{_code(err)}: {err.response['Error'].get('Message')}"
    return str(err)


def params_of(ctx: Dict[str, Any], control: str) -> Dict[str, Any]:
    return (ctx.get("params") or {}).get(control) or {}


def _list(v) -> List[Any]:
    return [v] if isinstance(v, (str, dict)) else list(v or [])


def statements(doc: Any) -> List[Dict[str, Any]]:
    doc = json.loads(unquote(doc)) if isinstance(doc, str) else (doc or {})
    return _list(doc.get("Statement"))


# ---- PS.1 · CodeBuild em modo privilegiado ------------------------------------------------------

def check_privileged(clients, res: Dict[str, Any], ctx: Dict[str, Any]) -> Result:
    """PS.1: o droide com acesso root ao host. O modo privilegiado roda o Docker daemon dentro do build:
    um buildspec comprometido ganha muito mais do que precisava."""
    env = res["meta"].get("environment") or {}
    privileged = bool(env.get("privilegedMode"))
    state = {"privilegedMode": privileged, "image": env.get("image")}
    state["reason"] = "PRIVILEGED_MODE" if privileged else "OK"
    return (FAIL if privileged else PASS), state


# ---- PS.2 · Segredo em texto puro na variável de ambiente --------------------------------------

def plaintext_secrets(project: Dict[str, Any], patterns: List[str]) -> List[str]:
    """Nomes (nunca valores) das variáveis PLAINTEXT que parecem segredo, pelo nome ou pelo valor."""
    found = []
    for var in (project.get("environment") or {}).get("environmentVariables") or []:
        if (var.get("type") or "PLAINTEXT") != "PLAINTEXT":
            continue
        name = var.get("name") or ""
        if any(fnmatch.fnmatchcase(name.upper(), p.upper()) for p in patterns) or AWS_KEY_VALUE.search(var.get("value") or ""):
            found.append(name)
    return found


def check_plaintext_secret(clients, res: Dict[str, Any], ctx: Dict[str, Any]) -> Result:
    """PS.2: a senha no bolso do droide. Variável PLAINTEXT aparece no console, no batch-get-projects e no log."""
    patterns = params_of(ctx, "PS.2").get("name_patterns") or DEFAULT_SECRET_NAMES
    names = plaintext_secrets(res["meta"], patterns)
    state = {"plaintextSecrets": names}
    state["reason"] = "PLAINTEXT_SECRET" if names else "OK"
    return (FAIL if names else PASS), state


# ---- PS.3 · CodeBuild sem logs de build ----------------------------------------------------------

def check_build_logs(clients, res: Dict[str, Any], ctx: Dict[str, Any]) -> Result:
    """PS.3: o droide que trabalha sem gravar nada. Sem log de build, não dá para saber o que o build fez."""
    logs = res["meta"].get("logsConfig") or {}
    cw = (logs.get("cloudWatchLogs") or {}).get("status", "ENABLED")   # sem logsConfig, o CodeBuild usa o CloudWatch
    s3 = (logs.get("s3Logs") or {}).get("status", "DISABLED")
    state = {"cloudWatchLogs": cw, "s3Logs": s3}
    ok = "ENABLED" in (cw, s3)
    state["reason"] = "OK" if ok else "NO_BUILD_LOGS"
    return (PASS if ok else FAIL), state


# ---- PS.4 · Notebook do SageMaker com root e internet direta --------------------------------------

def check_notebook(clients, res: Dict[str, Any], ctx: Dict[str, Any]) -> Result:
    """PS.4: o laboratório de ciência de dados com a porta da rua aberta e a chave de root na mão."""
    meta = res["meta"]
    gaps = []
    if meta.get("DirectInternetAccess", "Enabled") == "Enabled":
        gaps.append("DIRECT_INTERNET_ACCESS")
    if meta.get("RootAccess", "Enabled") == "Enabled":
        gaps.append("ROOT_ACCESS")
    state = {"gaps": gaps, "status": meta.get("NotebookInstanceStatus"), "subnet": bool(meta.get("SubnetId"))}
    state["reason"] = "NOTEBOOK_EXPOSED" if gaps else "OK"
    return (FAIL if gaps else PASS), state


# ---- PS.5 · RDS público -----------------------------------------------------------------------------

def check_rds_public(clients, res: Dict[str, Any], ctx: Dict[str, Any]) -> Result:
    """PS.5: o banco com endereço público. Mesmo com security group fechado, é um passo a menos para o atacante."""
    meta = res["meta"]
    public = bool(meta.get("PubliclyAccessible"))
    state = {"publiclyAccessible": public, "engine": meta.get("Engine"), "status": meta.get("DBInstanceStatus")}
    state["reason"] = "PUBLIC_DB" if public else "OK"
    return (FAIL if public else PASS), state


# ---- PS.6 · Service role com admin --------------------------------------------------------------------

def _role_documents(iam, role: str, ctx: Dict[str, Any]) -> List[Tuple[str, Any]]:
    cache = ctx.setdefault("role_docs", {})
    if role in cache:
        return cache[role]
    docs: List[Tuple[str, Any]] = []
    for p in _paginate(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role):
        if p["PolicyName"] == ADMIN_POLICY and p["PolicyArn"].endswith(":aws:policy/" + ADMIN_POLICY):
            docs.append((p["PolicyName"], {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
            continue
        if ":aws:policy/" in p["PolicyArn"]:
            continue   # as gerenciadas pela AWS (fora a AdministratorAccess) não são lidas: são muitas e já conhecidas
        version = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
        docs.append((p["PolicyName"], iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=version)["PolicyVersion"]["Document"]))
    for name in _paginate(iam, "list_role_policies", "PolicyNames", RoleName=role):
        docs.append((name, iam.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"]))
    cache[role] = docs
    return docs


def is_full_admin(stmt: Dict[str, Any]) -> bool:
    return stmt.get("Effect") == "Allow" and not stmt.get("Condition") \
        and "*" in _list(stmt.get("Action")) and "*" in _list(stmt.get("Resource"))


def _protected(res: Dict[str, Any]) -> bool:
    return res["name"].startswith(PROTECTED_ROLE_PREFIXES)


def check_service_role_admin(clients, res: Dict[str, Any], ctx: Dict[str, Any]) -> Result:
    """PS.6: o R2-D2 tem acesso a tudo da nave. Por isso cada plug dele importa: service role com admin
    entrega a conta inteira para qualquer código que o serviço rodar."""
    via = [name for name, doc in _role_documents(clients["iam"], res["locator"], ctx) if any(is_full_admin(s) for s in statements(doc))]
    state = {"services": res["meta"]["Services"], "adminVia": via}
    if _protected(res):
        state.update(reportOnly=True, reportOnlyReason="Role do Control Tower, Organizations ou StackSets: só reportar")
    state["reason"] = "SERVICE_ROLE_ADMIN" if via else "OK"
    return (FAIL if via else PASS), state


# ---- PS.7 · Confused deputy na trust policy -------------------------------------------------------------

def deputy_gaps(trust: Dict[str, Any], services: List[str]) -> List[Dict[str, Any]]:
    """Statements que deixam um serviço de `services` assumir a role sem aws:SourceAccount, aws:SourceArn
    ou aws:SourceOrgID: qualquer conta que usar aquele serviço pode, em tese, fazê-lo agir com a sua role."""
    gaps = []
    for idx, s in enumerate(statements(trust)):
        principal = s.get("Principal") if isinstance(s.get("Principal"), dict) else {}
        hit = [svc for svc in _list(principal.get("Service")) if svc in services]
        if s.get("Effect") != "Allow" or not hit:
            continue
        keys = {k.lower() for op in (s.get("Condition") or {}).values() for k in (op or {})}
        if not keys & set(DEPUTY_CONDITION_KEYS):
            gaps.append({"statement": s.get("Sid") or idx, "services": hit})
    return gaps


def check_confused_deputy(clients, res: Dict[str, Any], ctx: Dict[str, Any]) -> Result:
    """PS.7: o droide de protocolo que obedece qualquer um. A trust policy precisa dizer de QUAL conta
    o serviço pode vir (aws:SourceAccount ou aws:SourceArn)."""
    services = params_of(ctx, "PS.7").get("services") or DEFAULT_DEPUTY_SERVICES
    gaps = deputy_gaps(res["meta"]["Trust"], services)
    state = {"services": res["meta"]["Services"], "gaps": gaps}
    if not set(res["meta"]["Services"]) & set(services):
        state["reason"] = "SERVICE_NOT_LISTED"
        return NOT_APPLICABLE, state
    if _protected(res):
        state.update(reportOnly=True, reportOnlyReason="Role do Control Tower, Organizations ou StackSets: só reportar")
    state["reason"] = "CONFUSED_DEPUTY_RISK" if gaps else "OK"
    return (FAIL if gaps else PASS), state


CHECKS = {
    "PS.1": ("codebuild", check_privileged),
    "PS.2": ("codebuild", check_plaintext_secret),
    "PS.3": ("codebuild", check_build_logs),
    "PS.4": ("notebook", check_notebook),
    "PS.5": ("rds", check_rds_public),
    "PS.6": ("servicerole", check_service_role_admin),
    "PS.7": ("servicerole", check_confused_deputy),
}


# Estado esperado depois do apply, mostrado no preview do plan. Controle novo? Descreva aqui também.
EXPECTED = {
    "PS.1": "privilegedMode desligado (ou exceção com dono, para quem constrói imagem Docker)",
    "PS.2": "variável do tipo PARAMETER_STORE apontando para /ps-control-plane/<projeto>/<VARIAVEL> (SecureString)",
    "PS.3": "logs de build no CloudWatch Logs, no grupo /aws/codebuild/<projeto>",
    "PS.4": "DirectInternetAccess=Disabled (com VPC) e RootAccess=Disabled",
    "PS.5": "PubliclyAccessible=false",
    "PS.6": "service role com política de menor privilégio, sem Allow * em *",
    "PS.7": "trust policy com aws:SourceAccount igual à própria conta",
}


def expected_state(control: str, params: Dict[str, Any]) -> Dict[str, Any]:
    state: Dict[str, Any] = {"status": PASS, "description": EXPECTED.get(control, "conforme")}
    if control == "PS.3":
        state["retentionDays"] = params.get("retention_days", 90)
    return state


def verify(control: str, clients, res: Dict[str, Any], ctx: Dict[str, Any]) -> Result:
    kind, fn = CHECKS[control]
    try:
        return fn(clients, res, ctx)
    except ClientError as err:
        return ERROR, {"reason": "ERROR", "error": _error_detail(err)}


def _resource(kind: str, res: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": KINDS[kind]["type"], "kind": kind, "id": res.get("locator"), "name": res.get("name")}


def _item(control: str, rule: Dict[str, Any], status: str, resource: Dict[str, Any],
          state: Dict[str, Any], detail: str = "") -> Dict[str, Any]:
    item = {
        "control": control,
        "title": rule.get("title", control),
        "status": status,
        "resource": resource,
        "verified_state": state,
        "detail": detail,
        "severity": rule.get("severity"),
        "mitre": rule.get("mitre", []) or [],
    }
    if rule.get("securityhub_id"):
        item["securityhub_id"] = rule["securityhub_id"]
    return item


def kinds_of(control: str) -> Tuple[str, ...]:
    kind = CHECKS[control][0]
    return GROUP_KINDS.get(kind, (kind,))


def evaluate(clients, rules_doc: Dict[str, Any], ctx: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Avalia todos os controles do mapa. Devolve (escopo, itens).

    Cada tipo de recurso é listado uma vez só. Recurso fora do escopo não vira
    item: só entra na contagem `outOfScope`, para você saber que ele existe."""
    controls = rules_doc.get("controls", {}) or {}
    targets = rules_doc.get("targets") or {"mode": "tagged", "tag": {}}
    exc_cfg = rules_doc.get("exception", {}) or {}
    ctx.setdefault("params", {}).update({c: (r or {}).get("params") or {} for c, r in controls.items()})
    scope: Dict[str, Any] = {"mode": targets.get("mode"), "tag": targets.get("tag"), "inScope": {}, "outOfScope": {}}
    inventory: Dict[str, Any] = {}
    items: List[Dict[str, Any]] = []

    for control in sorted(controls, key=lambda c: (len(c), c)):
        rule = controls[control] or {}
        if control not in CHECKS:
            items.append(_item(control, rule, ERROR, {"type": None, "id": None, "name": None}, {"reason": "NO_CHECK"},
                               f"Sem verificador para {control} em scanner/checks.py (CHECKS)"))
            continue
        for kind in kinds_of(control):
            if kind not in inventory:
                try:
                    every = KINDS[kind]["list"](clients, ctx["region"])
                except ClientError as err:
                    inventory[kind] = err
                else:
                    scoped = KINDS[kind].get("scoped", True)
                    inventory[kind] = [dict(r, kind=kind) for r in every if not scoped or in_scope(r["tags"], targets)]
                    scope["inScope"][kind] = len(inventory[kind])
                    scope["outOfScope"][kind] = len(every) - len(inventory[kind])
            if isinstance(inventory[kind], ClientError):
                items.append(_item(control, rule, ERROR, {"type": KINDS[kind]["type"], "id": None, "name": None},
                                   {"reason": "ERROR"}, _error_detail(inventory[kind])))
                continue
            for res in inventory[kind]:
                status, state = verify(control, clients, res, ctx)
                item = _item(control, rule, status, _resource(kind, res), state, state.pop("error", ""))
                exception = exception_of(res["tags"], exc_cfg)
                if exception:
                    item["exception"] = exception
                items.append(item)
    return scope, items
