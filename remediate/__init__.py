"""Ações de remediação: uma função pequena por tipo de correção.

Toda ação recebe (clients, res, params, ctx, dry_run) e devolve um dict com
ok, message e changes. `res` é o recurso lido AO VIVO pelo remediate/engine.py,
que também confere escopo, exceção e estado antes de chamar a ação e confere de
novo depois (VERIFIED). Em dry-run nenhuma API de escrita é chamada.

Regras do módulo: nenhuma ação apaga projeto, notebook, banco ou role, e nenhum valor
de variável de ambiente vai para `changes` ou para a tela. Toda mudança guarda o antes.

Ação nova? Crie o arquivo aqui e registre o nome usado no `action:` do controle.
"""

from remediate.codebuild_enable_logs import run as codebuild_enable_logs
from remediate.codebuild_secret_to_ssm import run as codebuild_secret_to_ssm
from remediate.rds_disable_public import run as rds_disable_public
from remediate.role_trust_source_account import run as role_trust_source_account

REGISTRY = {
    "codebuild_secret_to_ssm": codebuild_secret_to_ssm,      # PS.2
    "codebuild_enable_logs": codebuild_enable_logs,          # PS.3
    "rds_disable_public": rds_disable_public,                # PS.5
    "role_trust_source_account": role_trust_source_account,  # PS.7
}
