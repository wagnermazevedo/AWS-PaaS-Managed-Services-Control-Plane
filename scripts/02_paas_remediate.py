#!/usr/bin/env python3
"""[02] REMEDIATE: executa os itens AUTO do plano. Dry-run é o padrão.

Cada item passa pelo remediate/engine.py: lê o recurso ao vivo, confere escopo e
exceção, age e confere de novo (VERIFIED). Itens MANUAL e EXCEPTION são
registrados, nunca tocados.

Saída: <output-dir>/<timestamp>/paas_remediation_results.{json,csv} e summary.md.
(Não grava YAML de propósito: o test-control-plane.sh procura o YAML de scan mais recente.)
"""

import argparse
import os

import _bootstrap  # noqa: F401

from lib import API_VERSION, mask
from lib.aws import SERVICES, client, session
from lib.io import DEFAULT_OUTPUTS, DEFAULT_PLAN, load_yaml, markdown_table, new_run_dir, utc_timestamp, write_csv, write_json, write_text
from lib.scope import LAB_PREFIXES, learn_resource_names, partition
from remediate import REGISTRY
from remediate.engine import execute

CSV_FIELDS = ["itemId", "control", "decision", "action", "resource", "ok", "message"]


def main():
    mask.setup(keep_prefixes=LAB_PREFIXES)  # modo gravação: antes do argparse, que não conhece --no-mask
    parser = argparse.ArgumentParser(description="AWS PaaS & Managed Services Remediate")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--yaml", default=DEFAULT_PLAN, help="Plano gerado pelo 01_paas_plan.py. Padrão: outputs/remediation_plan.yaml")
    parser.add_argument("--mode", choices=["dry-run", "apply"], default="dry-run")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUTS)
    args = parser.parse_args()

    if not os.path.exists(args.yaml):
        raise SystemExit(f"[ERRO] Plano não encontrado: {args.yaml}. Rode o 00 (scan) e o 01 (plan) antes do remediate.")
    plan = load_yaml(args.yaml)
    if plan.get("kind") != "PaasRemediationPlan":
        raise SystemExit(f"[ERRO] {args.yaml} não é um plano (kind={plan.get('kind')}). Rode o 01_paas_plan.py")
    metadata = plan.get("metadata") or {}
    if metadata.get("region") and metadata["region"] != args.region:
        raise SystemExit(f"[ERRO] O plano é da região {metadata['region']} e você pediu {args.region}. Rode o scan nesta região.")
    guardrails = metadata.get("guardrails") or {}
    if not (guardrails.get("targets") or {}).get("mode"):
        raise SystemExit("[ERRO] O plano não traz o escopo (guardrails). Gere de novo com o 01_paas_plan.py")

    dry_run = args.mode == "dry-run"
    sess = session(args.profile, args.region)
    clients = {svc: client(sess, svc) for svc in SERVICES}
    # sim: estado simulado compartilhado entre ações da mesma execução (ex.: a chave do módulo "criada" no dry-run).
    account = clients["sts"].get_caller_identity().get("Account")
    if metadata.get("callerAccountId") not in (None, account, "123456789012"):  # 123456789012 = cópia anonimizada
        raise SystemExit("[ERRO] O plano foi gerado em outra conta. Rode o scan e o plan nesta conta.")
    ctx = {"region": args.region, "partition": partition(args.region), "account": account, "guardrails": guardrails, "sim": {}}

    items = (plan.get("spec") or {}).get("items", []) or []
    learn_resource_names(i.get("resource") for i in items)
    summary = {"total": len(items), "executed": 0, "succeeded": 0, "failed": 0, "manual": 0, "exception": 0, "noAction": 0}
    results = []

    for item in items:
        decision = (item.get("decision") or {}).get("type", "MANUAL")
        action = item.get("action") or {}
        action_name = action.get("name", "manual")
        resource = item.get("resource") or {}
        entry = {"itemId": item.get("id"), "control": item.get("control"), "decision": decision,
                 "action": action_name, "resource": resource.get("name") or resource.get("id")}

        if decision == "AUTO":
            handler = REGISTRY.get(action_name)
            summary["executed"] += 1
            if not handler:
                outcome = {"ok": False, "message": f"UNSUPPORTED_ACTION: {action_name}", "changes": []}
            else:
                try:
                    outcome = execute(clients, item, handler, action.get("params") or {}, ctx, dry_run)
                except Exception as err:  # registra e segue: um item quebrado não para os outros
                    outcome = {"ok": False, "message": f"ERROR: {err}", "changes": []}
            summary["succeeded" if outcome["ok"] else "failed"] += 1
            entry.update(ok=outcome["ok"], message=outcome["message"], changes=outcome.get("changes", []))
        elif decision == "EXCEPTION":
            summary["exception"] += 1
            entry.update(ok=True, message="EXCEPTION: " + (item.get("decision") or {}).get("reason", ""))
        elif decision == "NO_ACTION":
            summary["noAction"] += 1
            entry.update(ok=True, message="NO_ACTION")
        else:
            summary["manual"] += 1
            entry.update(ok=False, message="MANUAL_REQUIRED: " + (item.get("decision") or {}).get("reason", ""))
        results.append(entry)

    timestamp = utc_timestamp()
    out = {
        "apiVersion": API_VERSION,
        "kind": "PaasRemediationResults",
        "metadata": {"executedAt": timestamp, "region": args.region, "mode": args.mode, "sourcePlan": os.path.abspath(args.yaml)},
        "spec": {"summary": summary, "results": results},
    }
    out_dir = new_run_dir(args.output_dir, timestamp)
    write_json(os.path.join(out_dir, "paas_remediation_results.json"), out)
    write_csv(os.path.join(out_dir, "paas_remediation_results.csv"), results, CSV_FIELDS)
    visible = [r for r in results if r["decision"] != "NO_ACTION"]
    write_text(os.path.join(out_dir, "summary.md"),
               f"# PaaS & Managed Services Remediate · {args.mode.upper()} · {timestamp}\n\n"
               + "\n".join(f"- {k}: {v}" for k, v in summary.items()) + "\n\n"
               + markdown_table(visible, ["control", "decision", "resource", "ok", "message"]))

    print(f"[OK] Remediação de PaaS & Managed Services finalizada ({args.mode.upper()}): {out_dir}")
    for key, value in summary.items():
        print(f" - {key:<10}: {value}")
    for r in visible:
        print(f"   {r['control']:<5} {r['decision']:<10} {str(r['resource']):<34} {r['message']}")
    if summary["failed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
