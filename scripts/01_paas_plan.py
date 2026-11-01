#!/usr/bin/env python3
"""[01] PLAN: cruza cada item do scan com o mapa de PaaS. Não chama a AWS.

Sem argumentos, pega sozinho o scan mais recente em outputs/ e grava
outputs/remediation_plan.yaml, que é o que o remediate lê.

Decisões possíveis por item:
  AUTO       -> o remediate corrige (ação e parâmetros vêm do arquivo do controle)
  MANUAL     -> fica para revisão humana, com o motivo e o runbook
  EXCEPTION  -> recurso com a tag de exceção e dono definido; não é corrigido
  NO_ACTION  -> item conforme ou não aplicável
"""

import argparse
import os
from typing import Any, Dict, Tuple

import _bootstrap  # noqa: F401

from lib import API_VERSION, mask
from lib.io import DEFAULT_OUTPUTS, DEFAULT_PLAN, latest_file, load_yaml, repo_path, write_yaml
from lib.rules import RulesError, load_rules
from lib.scope import LAB_PREFIXES, learn_resource_names
from scanner.checks import expected_state

SCAN_FILE = "paas_scan_export.yaml"


def decide(item: Dict[str, Any], controls: Dict[str, Any], exc_cfg: Dict[str, Any]) -> Tuple[str, str, str, Dict[str, Any]]:
    """Devolve (decisão, motivo, ação, parâmetros)."""
    control = item.get("control")
    status = item.get("status")
    rule = controls.get(control)

    if status in ("PASS", "NOT_APPLICABLE"):
        return "NO_ACTION", f"Status {status}", "none", {}
    if status == "ERROR":
        return "MANUAL", "Scan não conseguiu avaliar o item: " + (item.get("detail") or ""), "manual", {}
    if not rule:
        return "MANUAL", f"Controle {control} não está no mapa de PaaS", "manual", {}

    exception = item.get("exception")
    if exception:
        if exception.get("owner"):
            return ("EXCEPTION",
                    f"Tag {exc_cfg.get('tag_key')}: {exception.get('justification')} (dono: {exception['owner']})",
                    "none", {})
        return "MANUAL", "Exceção sem dono não vale: adicione a tag " + exc_cfg.get("owner_tag_key", "exception-owner"), "manual", {}

    state = item.get("verified_state") or {}
    if state.get("reportOnly"):
        return "MANUAL", state.get("reportOnlyReason") or "Recurso só reportado, nunca alterado pelo módulo", "manual", {}

    if rule.get("decision") != "AUTO":
        reason = rule.get("reason", "Mapa define tratamento manual")
        if rule.get("runbook"):
            reason += f" · runbook: {rule['runbook']}"
        return "MANUAL", reason, "manual", {}

    return "AUTO", f"Controle {control}: {rule.get('title', '')}", rule.get("action", "manual"), rule.get("params") or {}


def main():
    mask.setup(keep_prefixes=LAB_PREFIXES)  # modo gravação: antes do argparse, que não conhece --no-mask
    parser = argparse.ArgumentParser(description="AWS PaaS & Managed Services Plan (não altera recursos)")
    parser.add_argument("--input-yaml", default=None,
                        help="YAML gerado pelo 00_paas_scan.py. Padrão: o scan mais recente em outputs/")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUTS, help="Onde procurar o scan mais recente")
    parser.add_argument("--rules", default=repo_path("config", "paas_map.yaml"), help="Padrão: config/paas_map.yaml")
    parser.add_argument("--output-yaml", default=DEFAULT_PLAN, help="Padrão: outputs/remediation_plan.yaml")
    args = parser.parse_args()
    if not args.input_yaml:
        try:
            args.input_yaml = latest_file(args.output_dir, SCAN_FILE)
        except FileNotFoundError as err:
            raise SystemExit(f"[ERRO] {err}")
        print(f"[INFO] Usando o scan mais recente: {args.input_yaml}")

    doc = load_yaml(args.input_yaml)
    if doc.get("kind") != "PaasFindingsExport":
        raise SystemExit(f"[ERRO] {args.input_yaml} não é um export de scan (kind={doc.get('kind')})")

    try:
        rules_doc = load_rules(args.rules)
    except (RulesError, FileNotFoundError) as err:
        raise SystemExit(f"[ERRO] Mapa de PaaS inválido: {err}")
    controls = rules_doc["controls"]
    exc_cfg = rules_doc.get("exception", {}) or {}

    items = (doc.get("spec") or {}).get("items", []) or []
    learn_resource_names(i.get("resource") for i in items)
    counts: Dict[str, int] = {"AUTO": 0, "MANUAL": 0, "EXCEPTION": 0, "NO_ACTION": 0}
    for item in items:
        decision, reason, action, params = decide(item, controls, exc_cfg)
        counts[decision] += 1
        item["decision"] = {"type": decision, "reason": reason}
        item["action"] = {"name": action, "params": params}
        if decision == "AUTO":
            item["expected_state"] = expected_state(item["control"], params)

    order = lambda c: (len(c or ""), c or "")  # noqa: E731  ID.2 antes de ID.10
    items.sort(key=lambda i: (i.get("decision", {}).get("type") != "AUTO", order(i.get("control")), i.get("id", "")))

    plan = {
        "apiVersion": API_VERSION,
        "kind": "PaasRemediationPlan",
        "metadata": {
            **(doc.get("metadata") or {}),
            "plannedBy": "01_paas_plan.py",
            "sourceScan": os.path.abspath(args.input_yaml),
            "rulesFile": args.rules,
            # O remediate confere de novo, ao vivo, se o recurso ainda está no escopo e sem exceção.
            "guardrails": {"targets": rules_doc["targets"], "exception": exc_cfg},
            "planSummary": {"totalItems": len(items), **{k.lower(): v for k, v in counts.items()}},
        },
        "spec": {"items": items},
    }
    write_yaml(args.output_yaml, plan)

    print(f"[OK] Plano de PaaS & Managed Services gerado: {args.output_yaml}")
    print(f" - Total     : {len(items)}")
    for key in ("AUTO", "MANUAL", "EXCEPTION", "NO_ACTION"):
        print(f" - {key:<10}: {counts[key]}")
    print("\n Preview do impacto (estado atual -> esperado):")
    for item in items:
        decision = item["decision"]["type"]
        if decision == "NO_ACTION":
            continue
        resource = item.get("resource") or {}
        current = (item.get("verified_state") or {}).get("reason") or item.get("status")
        target = item["expected_state"]["description"] if decision == "AUTO" else decision.lower()
        print(f"   {item['control']:<5} {decision:<10} {resource.get('name') or resource.get('id') or '-':<34} {current} -> {target}")


if __name__ == "__main__":
    main()
