# Arquitetura

```text
 99_paas_lab_setup.py ──► stack ps-control-plane-lab (tudo com a tag ps-lab=true, custo zero)
                            │   projetos ps-lab-droid-factory, -bb8, -k2so; roles ps-lab-r2d2 e -c3po
                            │   (as duas com o boundary ps-lab-boundary)
                            ▼
 00_paas_scan.py ── CodeBuild, SageMaker, RDS e IAM (só leitura; nenhum valor de variável é gravado)
               ├──► scanner/inventory.py  (projetos, notebooks, bancos e service roles; separa o escopo)
               └──► scanner/checks.py     (PS.1 a PS.7)
                            │
            outputs/<data-hora>/paas_scan_export.yaml
                            │
 01_paas_plan.py ── config/paas_map.yaml + config/controls/PS.N.yaml
                            │   AUTO / MANUAL / EXCEPTION / NO_ACTION + preview
                    outputs/remediation_plan.yaml
                            │
 02_paas_remediate.py ──► remediate/engine.py, para cada item AUTO:
   lê ao vivo · confere escopo e exceção · NOOP se já PASS · age (ou descreve, em dry-run) · VERIFIED
     PS.2 ─► SSM PutParameter (SecureString) ─► IAM PutRolePolicy (ps-control-plane-access) ─► CodeBuild UpdateProject
     PS.3 ─► Logs CreateLogGroup + retenção  ─► IAM PutRolePolicy                          ─► CodeBuild UpdateProject
     PS.5 ─► RDS ModifyDBInstance (PubliclyAccessible=false)
     PS.7 ─► IAM UpdateAssumeRolePolicy (+ aws:SourceAccount)
                            │
     outputs/<data-hora>/paas_remediation_results.{json,csv} + summary.md
```

## Decisões de projeto

- **Quatro droides, um inventário.** Projetos do CodeBuild, notebooks do SageMaker, bancos do RDS e service roles. Service role é toda role cuja trust policy tem `Principal.Service`. As service-linked (`/aws-service-role/`) e as do Identity Center (`/aws-reserved/`) nem entram.
- **Segredo nunca sai da conta.** O scan guarda só o nome da variável. O PS.2 lê o valor ao vivo, no apply, e grava direto no Parameter Store. O teste `test_secret_values_never_leave_the_account` varre todos os arquivos gerados e a tela atrás do valor.
- **Escopo da role é da role.** O PS.2 e o PS.3 precisam dar permissão à service role do projeto. Se a role não tiver as tags do escopo, a correção é `REFUSED` antes de qualquer escrita, com o que fazer à mão.
- **Permissão mínima e rastreável.** Tudo o que o módulo dá a uma role fica numa política inline só dele (`ps-control-plane-access`), com um `Sid` por projeto e por motivo (`ReadParams…`, `WriteLogs…`), restrito ao caminho do parâmetro ou ao grupo de log. O `--destroy` tira essa política antes de apagar a stack.
- **Confused deputy com lista.** O PS.7 vale para os serviços em que a AWS recomenda `aws:SourceAccount`/`aws:SourceArn` (CodeBuild, SageMaker, CodePipeline, Glue, Step Functions, EventBridge e outros). Role de EC2 ou Lambda fica `NOT_APPLICABLE`. A correção acrescenta `aws:SourceAccount` igual à própria conta: quem usa a role aqui continua usando.
- **Decisão com dono.** Modo privilegiado (PS.1), notebook (PS.4) e admin em service role (PS.6) são MANUAL: a correção automática quebraria build, notebook ou pipeline.
- **Roles da casa.** Control Tower, Organizations e StackSets: `reportOnly`, o plan mantém MANUAL.
- **Lab sem custo e sem risco.** Só IAM e CodeBuild parado. As roles têm um boundary que só deixa escrever log de build e ler os parâmetros do módulo. Notebook e RDS ficam nos testes offline.
- **Nada é apagado.** Nenhuma ação apaga projeto, notebook, banco ou role. Toda mudança guarda o antes.
- **Ligação com os outros episódios.** Ep. 4: o Parameter Store usa a chave `aws/ssm` do KMS. Ep. 5: PS.6 é o ID.3 para quem não é gente. Ep. 6: segredo em variável de ambiente é uma credencial esperando para vazar. Ep. 7: banco sem IP público é acessado pela VPC, com Session Manager. Ep. 9: o log de build que o PS.3 liga é evidência.
