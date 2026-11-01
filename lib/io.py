"""Leitura e escrita de artefatos versionados (YAML, JSON, CSV, Markdown).

Regra do template: saídas nunca são sobrescritas. Cada execução ganha a sua
própria pasta com data e hora; se a pasta já existir, um sufixo é adicionado.

Modo gravação (lib/mask.py): CSV e summary.md saem mascarados, porque são feitos
para gente ver. YAML e JSON ficam com os valores reais: o plan e o remediate
precisam deles. Nenhum script lê CSV ou summary.md de volta.
"""

import csv
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

import yaml

from lib import mask

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def repo_path(*parts: str) -> str:
    return os.path.join(REPO_ROOT, *parts)


# Pasta padrão das saídas: sempre dentro do repositório, de onde quer que o script seja chamado.
DEFAULT_OUTPUTS = os.path.join(REPO_ROOT, "outputs")
DEFAULT_PLAN = os.path.join(DEFAULT_OUTPUTS, "remediation_plan.yaml")


def latest_file(base_dir: str, filename: str) -> str:
    """O arquivo `filename` mais recente dentro de base_dir/<timestamp>/ (por data de modificação)."""
    import glob
    found = glob.glob(os.path.join(base_dir, "*", filename))
    if not found:
        raise FileNotFoundError(f"Nenhum {filename} em {base_dir}/. Rode o scan primeiro.")
    return max(found, key=os.path.getmtime)


def new_run_dir(base_dir: str, timestamp: str) -> str:
    path = os.path.join(base_dir, timestamp)
    suffix = 1
    while os.path.exists(path):
        path = os.path.join(base_dir, f"{timestamp}_{suffix:02d}")
        suffix += 1
    os.makedirs(path)
    return path


def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_yaml(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)


def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def write_csv(path: str, rows: Iterable[Dict[str, Any]], fields: List[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(mask.mask_value(row) if mask.enabled() else row)


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(mask.mask_text(text) if mask.enabled() else text)


def markdown_table(rows: List[Dict[str, Any]], fields: List[str]) -> str:
    if not rows:
        return "_Nenhum item._\n"
    lines = ["| " + " | ".join(fields) + " |", "|" + "---|" * len(fields)]
    for row in rows:
        cells = [str(row.get(field, "")).replace("|", "\\|").replace("\n", " ") for field in fields]
        if mask.enabled():
            cells = [mask.mask_text(c) for c in cells]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"
