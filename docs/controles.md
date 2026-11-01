# Controles

| ID | Pergunta | Tipo | O que verifica | PASS quando | Decisão | Ação | Security Hub |
|---|---|---|---|---|---|---|---|
| PS.1 | O que carrega no bolso? | codebuild | `environment.privilegedMode` | Desligado | MANUAL | runbook | CodeBuild.5 |
| PS.2 | O que carrega no bolso? | codebuild | Variáveis `PLAINTEXT` com nome de segredo (`name_patterns`) ou valor com cara de access key | Nenhuma | AUTO | `codebuild_secret_to_ssm` | CodeBuild.2 |
| PS.3 | O que carrega no bolso? | codebuild | `logsConfig` (CloudWatch e S3) | Algum dos dois `ENABLED` (sem `logsConfig`, o padrão é CloudWatch ligado) | AUTO | `codebuild_enable_logs` | CodeBuild.4 |
| PS.4 | Está exposto? | notebook | `DirectInternetAccess` e `RootAccess` | Os dois `Disabled` | MANUAL | runbook | SageMaker.1, SageMaker.3 |
| PS.5 | Está exposto? | rds | `PubliclyAccessible` | `false` | AUTO | `rds_disable_public` | RDS.2 |
| PS.6 | Com qual role roda? | servicerole | `AdministratorAccess`, ou Allow `*` em `*` sem condição, em política gerenciada pelo cliente ou inline | Nenhuma | MANUAL | runbook | — |
| PS.7 | Com qual role roda? | servicerole | Statement que deixa um serviço da lista `services` assumir a role | Com `aws:SourceAccount`, `aws:SourceArn`, `aws:SourceOrgID` ou `aws:SourceOrgPaths` | AUTO | `role_trust_source_account` | — |

## Motivos (`verified_state.reason`)

| Controle | Motivos |
|---|---|
| PS.1 | `OK`, `PRIVILEGED_MODE` |
| PS.2 | `OK`, `PLAINTEXT_SECRET` (só os nomes em `plaintextSecrets`) |
| PS.3 | `OK`, `NO_BUILD_LOGS` |
| PS.4 | `OK`, `NOTEBOOK_EXPOSED` (com `DIRECT_INTERNET_ACCESS` e/ou `ROOT_ACCESS` em `gaps`) |
| PS.5 | `OK`, `PUBLIC_DB` |
| PS.6 | `OK`, `SERVICE_ROLE_ADMIN` (com as políticas em `adminVia`; `reportOnly` nas roles do Control Tower) |
| PS.7 | `OK`, `CONFUSED_DEPUTY_RISK` (com os statements em `gaps`), `SERVICE_NOT_LISTED` (NOT_APPLICABLE) |

## Desfazendo uma correção à mão

```bash
# PS.2: voltar a variável para texto puro (o valor continua no parâmetro)
aws ssm get-parameter --name /ps-control-plane/<projeto>/<VARIAVEL> --with-decryption --query Parameter.Value --output text
#   e edite a variável no console do CodeBuild (Environment → Additional configuration)

# PS.2 e PS.3: tirar a permissão que o módulo deu à role
aws iam delete-role-policy --role-name <role> --policy-name ps-control-plane-access

# PS.5: devolver o endereço público
aws rds modify-db-instance --db-instance-identifier <banco> --publicly-accessible --apply-immediately

# PS.7: a trust policy anterior está em changes[0].trustPolicy.before
aws iam update-assume-role-policy --role-name <role> --policy-document file://trust-anterior.json
```
