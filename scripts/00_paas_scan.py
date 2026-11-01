#!/usr/bin/env python3
"""[00] SCAN: avalia os controles de PaaS e serviços gerenciados (PS.1 a PS.7). Somente leitura.

Só entram os recursos do escopo (por padrão, os que têm a tag ps-lab=true): projetos do CodeBuild,
notebooks do SageMaker, bancos do RDS e as service roles (roles que um serviço da AWS assume).

Saída (pasta nova por execução, nunca sobrescrita):
  <output-dir>/<timestamp>/paas_scan_export.yaml  -> entrada do plan
  <output-dir>/<timestamp>/paas_scan_export.json
  <output-dir>/<timestamp>/paas_scan_export.csv   -> Athena
  <output-dir>/<timestamp>/summary.md                       -> gente
"""

import argparse
import os
from collections import Counter

import _bootstrap  # noqa: F401

from lib import API_VERSION, mask
from lib.aws import SERVICES, client, session
from lib.io import DEFAULT_OUTPUTS, markdown_table, new_run_dir, repo_path, utc_timestamp, write_csv, write_json, write_text, write_yaml
from lib.rules import RulesError, load_rules
from lib.scope import LAB_PREFIXES, learn_resource_names, partition
from scanner.checks import evaluate

CSV_FIELDS = ["id", "control", "status", "severity", "resource_type", "resource_id", "resource_name",
              "reason", "exception_owner", "detail"]
KIND_LABELS = {'codebuild': 'projeto(s) do CodeBuild', 'notebook': 'notebook(s) do SageMaker', 'rds': 'banco(s) do RDS', 'servicerole': 'service role(s)'}


def flatten(item):
    resource = item.get("resource") or {}
    return {
        "id": item["id"],
        "control": item["control"],
        "status": item["status"],
        "severity": item.get("severity"),
        "resource_type": resource.get("type"),
        "resource_id": resource.get("id"),
        "resource_name": resource.get("name"),
        "reason": (item.get("verified_state") or {}).get("reason", ""),
        "exception_owner": (item.get("exception") or {}).get("owner") or "",
        "detail": item.get("detail", ""),
    }


def scope_line(scope):
    if scope.get("mode") == "all":
        who = "todos os recursos da região (targets.mode=all)"
    else:
        who = "recursos com a tag " + ", ".join(f"{k}={v}" for k, v in (scope.get("tag") or {}).items())
    out = {k: v for k, v in (scope.get("outOfScope") or {}).items() if v}
    ignored = ", ".join(f"{v} {KIND_LABELS.get(k, k)}" for k, v in out.items()) or "nenhum"
    return who, ignored


def main():
    mask.setup(keep_prefixes=LAB_PREFIXES)  # modo gravação: antes do argparse, que não conhece --no-mask
    parser = argparse.ArgumentParser(description="AWS PaaS & Managed Services Scan (somente leitura)")
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--rules", default=repo_path("config", "paas_map.yaml"), help="Padrão: config/paas_map.yaml")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUTS, help="Padrão: outputs/ do repositório")
    args = parser.parse_args()

    try:
        rules_doc = load_rules(args.rules)
    except (RulesError, FileNotFoundError) as err:
        raise SystemExit(f"[ERRO] Mapa de PaaS inválido: {err}")

    sess = session(args.profile, args.region)
    clients = {svc: client(sess, svc) for svc in SERVICES}
    caller = clients["sts"].get_caller_identity()
    ctx = {"region": args.region, "partition": partition(args.region), "account": caller.get("Account")}

    scope, items = evaluate(clients, rules_doc, ctx)
    for idx, item in enumerate(items, start=1):
        item["id"] = f"ps-item-{idx:06d}"
    learn_resource_names(i.get("resource") for i in items)

    timestamp = utc_timestamp()
    counts = Counter(i["status"] for i in items)
    export = {
        "apiVersion": API_VERSION,
        "kind": "PaasFindingsExport",
        "metadata": {
            "generatedAt": timestamp,
            "region": args.region,
            "source": "aws:ec2,aws:ssm,aws:s3",
            "callerAccountId": caller.get("Account"),
            "scope": scope,
            "rulesFile": os.path.relpath(args.rules, repo_path()),
            "controlFiles": rules_doc.get("included", []),
            "summary": dict(counts),
        },
        "spec": {"items": items},
    }

    out_dir = new_run_dir(args.output_dir, timestamp)
    write_yaml(os.path.join(out_dir, "paas_scan_export.yaml"), export)
    write_json(os.path.join(out_dir, "paas_scan_export.json"), export)
    rows = [flatten(i) for i in items]
    write_csv(os.path.join(out_dir, "paas_scan_export.csv"), rows, CSV_FIELDS)
    who, ignored = scope_line(scope)
    write_text(os.path.join(out_dir, "summary.md"),
               f"# PaaS & Managed Services Scan · {timestamp}\n\n"
               f"Conta: `{caller.get('Account')}` · Região: `{args.region}`\n\n"
               f"Escopo: {who} · Fora do escopo (ignorados): {ignored}\n\n"
               + markdown_table(rows, ["control", "status", "resource_name", "reason", "exception_owner", "detail"]))

    print(f"[OK] PaaS & Managed Services Scan concluído: {out_dir}/paas_scan_export.yaml")
    print(f" Escopo: {who} · fora do escopo: {ignored}")
    for status in ("FAIL", "PASS", "ERROR", "NOT_APPLICABLE"):
        print(f" - {status:<15}: {counts.get(status, 0)}")
    for row in rows:
        if row["status"] != "PASS":
            note = f" (exceção: {row['exception_owner']})" if row["exception_owner"] else ""
            print(f"   {row['control']:<5} {row['status']:<15} {row['resource_name'] or '-':<34} {row['reason'] or row['detail']}{note}")


if __name__ == "__main__":
    main()
