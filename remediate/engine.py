"""O passo a passo de todo item AUTO, igual para qualquer controle:

1. lê o recurso AO VIVO (o plano pode estar velho);
2. confere se ele ainda está no escopo e sem tag de exceção (alguém pode ter mexido nas tags);
3. avalia o controle: se já está PASS, não faz nada (NOOP);
4. chama a ação (em dry-run, a ação só descreve o que faria);
5. lê de novo e avalia: só PASS vira VERIFIED.
"""

import time
from typing import Any, Callable, Dict

from lib.scope import exception_of, in_scope
from scanner.checks import CHECKS, ERROR, NOT_APPLICABLE, PASS, verify
from scanner.inventory import KINDS, NotFound

TYPE_TO_KIND = {spec["type"]: kind for kind, spec in KINDS.items()}


def _fail(message: str) -> Dict[str, Any]:
    return {"ok": False, "message": message, "changes": []}


def execute(clients, item: Dict[str, Any], handler: Callable, params: Dict[str, Any],
            ctx: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    control = item.get("control")
    if control not in CHECKS:
        return _fail(f"NO_CHECK: {control} não tem verificador em scanner/checks.py")
    resource = item.get("resource") or {}
    kind = resource.get("kind") or TYPE_TO_KIND.get(resource.get("type"))
    if not kind:
        return _fail(f"REFUSED: tipo de recurso desconhecido ({resource.get('type')})")
    locator = resource.get("id")
    if kind != "account" and not locator:
        return _fail("REFUSED: item sem recurso")
    ctx.setdefault("params", {})[control] = params

    def load():
        return dict(KINDS[kind]["load"](clients, locator, ctx["region"]), kind=kind)

    # 1 e 2. Estado e tags ao vivo.
    try:
        res = load()
    except NotFound:
        return _fail(f"NOT_FOUND: {locator} não existe mais")
    guard = ctx.get("guardrails") or {}
    if KINDS[kind].get("scoped", True):
        if not in_scope(res["tags"], guard.get("targets") or {}):
            return _fail(f"REFUSED: {locator} não tem mais as tags do escopo; nada foi alterado")
        if exception_of(res["tags"], guard.get("exception") or {}):
            return _fail(f"REFUSED: {locator} ganhou a tag de exceção depois do plano; rode o scan e o plan de novo")

    # 3. Já conforme?
    status, state = verify(control, clients, res, ctx)
    if status == PASS:
        return {"ok": True, "message": f"NOOP: {control} já conforme em {res['name']}", "changes": []}
    if status in (NOT_APPLICABLE, ERROR):
        return _fail(f"{status}: {state.get('reason')} {state.get('error', '')}".strip())

    # 4. Corrige (ou descreve, em dry-run).
    outcome = handler(clients, res, params, ctx, dry_run)
    if dry_run or not outcome["ok"] or not outcome.get("changes"):
        return outcome

    # 5. Confere de novo. Algumas APIs levam alguns segundos para refletir a mudança.
    attempts, delay = ctx.get("verify_attempts", 6), ctx.get("verify_delay", 5)
    for attempt in range(attempts):
        status, state = verify(control, clients, load(), ctx)
        if status == PASS:
            outcome["message"] += " | VERIFIED"
            return outcome
        if attempt + 1 < attempts:
            time.sleep(delay)
    outcome.update(ok=False, message=outcome["message"] + f" | VERIFY_FAILED: {state.get('reason')}")
    return outcome
