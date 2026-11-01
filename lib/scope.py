"""Escopo e exceções: quem o módulo pode tocar.

Por padrão, só recursos com a tag do laboratório (targets.tag no mapa). A conta
pode ter projetos, notebooks e bancos de produção: esses nem entram no scan.

A service role é avaliada pelas tags dela. Um projeto do laboratório que usa uma role
de fora do escopo não dá ao módulo o direito de mexer nessa role: a correção que
precisaria dela vira REFUSED, com o motivo.
"""

from typing import Any, Dict, Iterable, Optional

# Modo gravação (lib/mask.py): nomes do laboratório que continuam legíveis na tela.
LAB_PREFIXES = (
    "ps-lab-",            # projetos e roles do laboratório
    "ps-control-plane",   # stack do lab, parâmetros e política inline que o módulo cria
    "/ps-control-plane",  # caminho dos parâmetros no Parameter Store
)

# Roles que o módulo nunca altera, mesmo com mode: all (Control Tower, Organizations, StackSets).
PROTECTED_ROLE_PREFIXES = ("AWSControlTower", "aws-controltower-", "OrganizationAccountAccessRole",
                           "AWSCloudFormationStackSet", "stacksets-exec-")


def in_scope(tags: Dict[str, str], targets: Dict[str, Any]) -> bool:
    if targets.get("mode") == "all":
        return True
    wanted = targets.get("tag") or {}
    # Sem tag configurada não existe escopo seguro: nada entra.
    return bool(wanted) and all(tags.get(k) == v for k, v in wanted.items())


def exception_of(tags: Dict[str, str], exc_cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = exc_cfg.get("tag_key")
    if not key or key not in tags:
        return None
    return {"justification": tags.get(key), "owner": tags.get(exc_cfg.get("owner_tag_key", "exception-owner"))}


def partition(region: str) -> str:
    if (region or "").startswith("cn-"):
        return "aws-cn"
    if (region or "").startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def learn_resource_names(resources: Iterable[Dict[str, Any]]) -> None:
    """Modo gravação: nomes de fora do laboratório (ex.: targets.mode=all) também viram apelido."""
    from lib import mask
    for res in resources:
        res = res or {}
        if res.get("name"):   # aqui o locator é o próprio nome: os do lab continuam legíveis (keep_prefixes)
            mask.learn([res.get("name")], "name")
