# Desafio da semana: PS.8, função Lambda com URL pública sem autenticação

**O problema.** Uma function URL com `AuthType: NONE` é um droide com a porta de serviço aberta para a galáxia inteira: qualquer um com o endereço chama a função, que roda com a role dela. Às vezes é de propósito (um webhook). Quase sempre, é esquecimento.

**A decisão.** MANUAL: trocar para `AWS_IAM` quebra quem chama sem assinar. O controle mostra quem está aberto e o dono decide (exceção com dono para o webhook de verdade).

## Os cinco passos

1. **Declare o controle** em `config/controls/PS.8.yaml`: `decision: MANUAL`, `securityhub_id: Lambda.1` (o mais próximo: policy de função pública), `reason` e um `runbook` para a documentação de function URLs.
2. **Inventário e scanner.** Em `scanner/inventory.py`, um tipo `lambda` com `list_functions` (`lambda.list_functions`, com as tags de `lambda.list_tags(Resource=arn)`) e `load_function`. Em `scanner/checks.py`, `check_function_url`, que chama `lambda.list_function_url_configs(FunctionName=...)`: alguma com `AuthType == "NONE"`, `FAIL` com `PUBLIC_FUNCTION_URL`. Registre em `CHECKS` e acrescente `"lambda"` ao `SERVICES` do `lib/aws.py`.
3. **Correção.** Não tem: é MANUAL. Escreva um bom `reason`.
4. **Laboratório.** Uma `AWS::Lambda::Function` pequena (inline, Python) com uma `AWS::Lambda::Url` `AuthType: NONE`, a tag `ps-lab` e a role com o `ps-lab-boundary`. Função parada não cobra.
5. **Testes.** No `tests/fakes.py`, um `FakeLambda` com `list_functions`, `list_tags` e `list_function_url_configs`. No `tests/test_control_plane.py`, uma função com URL `NONE` (FAIL), uma com `AWS_IAM` (PASS) e uma de produção, sem a tag (fora do escopo).

Rode `python3 -m unittest discover -s ~/AWS-PaaS-Managed-Services-Control-Plane/tests -v`, depois o ciclo completo, e mande o pull request.
