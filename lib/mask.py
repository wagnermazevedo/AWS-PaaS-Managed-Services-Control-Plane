"""Modo gravação: esconde valores reais da sua nuvem no que vai para a tela.

Ligado por padrão. Troca número de conta, IDs da organização, IDs de chave,
access keys, e-mails, IPs públicos, IDs de recursos e nomes de buckets fora do
laboratório por apelidos estáveis. O mesmo valor real vira sempre o mesmo
apelido (HMAC com uma chave local em outputs/.mask-key), então dá para
acompanhar a demo sem que ninguém consiga voltar ao valor original.

Vale para a saída do terminal, para o summary.md e para os CSVs. Os arquivos
YAML e JSON continuam com os valores reais, porque o plan e o remediate
precisam deles para agir. Para ver tudo real no terminal: --no-mask.
"""

import hashlib
import hmac
import ipaddress
import os
import re
import sys
from typing import Any, Iterable, Optional

ENV_FLAG = "SCP_MASK"  # SCP_MASK=0 desliga, igual a --no-mask

_KEY: Optional[bytes] = None
_ENABLED = True
_KEEP_PREFIXES: tuple = ()
_LEARNED: dict = {}
_ALIASES: set = set()

_ACCOUNT = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
_ORG = re.compile(r"\bo-[a-z0-9]{10,32}\b")
_OU = re.compile(r"\bou-[a-z0-9]{4,32}-[a-z0-9]{8,32}\b")
_ROOT = re.compile(r"\br-[a-z0-9]{4,32}\b")
_ACCESS_KEY = re.compile(r"\b(AKIA|ASIA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_RES_ID = re.compile(r"\b(sg|vpc|subnet|i|vol|eni|igw|nat|rtb|acl|snap|ami|eipalloc|pcx|tgw|vpce)-[0-9a-f]{8,17}\b")
_S3_ARN = re.compile(r"arn:(aws[a-z-]*):s3:::([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])")
_S3_URI = re.compile(r"s3://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])")
_IAM_USER = re.compile(r"(:user/)([A-Za-z0-9+=,.@_\-/]+)")

_SAFE_VALUES = {"123456789012", "000000000000"}  # contas de exemplo da documentação
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _key() -> bytes:
    global _KEY
    if _KEY is None:
        _KEY = _load_key()
    return _KEY


def _load_key() -> bytes:
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs", ".mask-key")
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) >= 32:
            return data
    except OSError:
        pass
    data = os.urandom(32)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o600)
    except OSError:
        pass  # sem disco gravável: apelidos estáveis só dentro desta execução
    return data


def _digest(kind: str, value: str) -> str:
    return hmac.new(_key(), f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()


def _digits(kind: str, value: str, n: int) -> str:
    return str(int(_digest(kind, value), 16))[-n:].zfill(n)


def alias(kind: str, value: str) -> str:
    """Apelido estável e com o mesmo formato do valor original."""
    if value in _ALIASES:
        return value  # já é um apelido: não mascara de novo
    out = _alias(kind, value)
    _ALIASES.add(out)
    return out


def _alias(kind: str, value: str) -> str:
    h = _digest(kind, value)
    if kind == "account":
        # Apelido visivelmente mascarado: 8 dígitos derivados (não reais) + XXXX no fim.
        return _digits(kind, value, 8) + "XXXX"
    if kind == "org":
        return "o-" + h[:8] + "XXXX"
    if kind == "ou":
        return f"ou-{h[:4]}-{h[4:12]}"
    if kind == "root":
        return "r-" + h[:4]
    if kind == "access_key":
        return value[:4] + "EXAMPLE" + h[:9].upper()
    if kind == "uuid":
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    if kind == "email":
        return f"user-{h[:6]}@example.com"
    if kind == "ip":
        return f"203.0.113.{int(h[:2], 16) % 254 + 1}"
    if kind == "bucket":
        return "bucket-" + h[:8]
    if kind == "user":
        return "user-" + h[:6]
    if kind == "name":
        return "nome-" + h[:6]
    if kind.startswith("res:"):
        prefix = kind[4:]
        return f"{prefix}-{h[:len(value) - len(prefix) - 1]}"
    return "masked-" + h[:8]


def setup(argv: Optional[Iterable[str]] = None, keep_prefixes: Iterable[str] = ()) -> bool:
    """Chame no começo do script. Tira --no-mask de sys.argv e liga o filtro no terminal."""
    global _ENABLED, _KEEP_PREFIXES
    argv = sys.argv if argv is None else argv
    _KEEP_PREFIXES = tuple(keep_prefixes)
    disabled = "--no-mask" in argv or os.environ.get(ENV_FLAG, "1").strip().lower() in ("0", "false", "no", "off")
    if isinstance(argv, list):
        while "--no-mask" in argv:
            argv.remove("--no-mask")
    _ENABLED = not disabled
    if _ENABLED and not isinstance(sys.stdout, _MaskedStream):
        sys.stdout = _MaskedStream(sys.stdout)
        sys.stderr = _MaskedStream(sys.stderr)
    return _ENABLED


def enabled() -> bool:
    return _ENABLED


def learn(values: Iterable[str], kind: str = "name") -> None:
    """Registra nomes reais (bucket, conta, fila...) para esconder também quando aparecem soltos no texto."""
    for v in values or ():
        if not v or not isinstance(v, str) or _kept(v) or v in _LEARNED:
            continue
        _LEARNED[v] = alias(kind, v)


def _kept(name: str) -> bool:
    return bool(_KEEP_PREFIXES) and name.startswith(_KEEP_PREFIXES)


def _public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_global and not any(ip in net for net in _DOC_NETS)


def mask_text(text: str) -> str:
    if not _ENABLED or not text:
        return text
    text = _replace_learned(text)

    def bucket(m: "re.Match") -> str:
        name = m.group(m.lastindex)
        if _kept(name):
            return m.group(0)
        _LEARNED.setdefault(name, alias("bucket", name))
        return m.group(0).replace(name, _LEARNED[name])

    text = _S3_ARN.sub(bucket, text)
    text = _S3_URI.sub(bucket, text)
    text = _IAM_USER.sub(lambda m: m.group(1) + alias("user", m.group(2)), text)
    text = _ACCESS_KEY.sub(lambda m: alias("access_key", m.group(0)), text)
    text = _OU.sub(lambda m: alias("ou", m.group(0)), text)
    text = _ORG.sub(lambda m: alias("org", m.group(0)), text)
    text = _ROOT.sub(lambda m: alias("root", m.group(0)), text)
    text = _UUID.sub(lambda m: alias("uuid", m.group(0)), text)
    text = _EMAIL.sub(lambda m: m.group(0) if m.group(0).endswith("@example.com") else alias("email", m.group(0)), text)
    text = _RES_ID.sub(lambda m: alias("res:" + m.group(1), m.group(0)), text)
    text = _ACCOUNT.sub(_account, text)
    text = _IPV4.sub(lambda m: alias("ip", m.group(0)) if _public_ip(m.group(0)) else m.group(0), text)
    return _replace_learned(text)  # de novo: pega nomes aprendidos nesta mesma linha


def _account(m: "re.Match") -> str:
    value = m.group(0)
    if value in _SAFE_VALUES:
        return value
    # Dígitos que fazem parte de um apelido já gerado (um UUID falso, por exemplo) não são conta.
    line = m.string
    for a in _ALIASES:
        if len(a) > 12 and value in a and a in line:
            return value
    return alias("account", value)


def _replace_learned(text: str) -> str:
    for real in sorted(_LEARNED, key=len, reverse=True):
        if real in text:
            text = text.replace(real, _LEARNED[real])
    return text


def mask_value(value: Any) -> Any:
    """Aplica mask_text em strings dentro de dicts e listas (para CSV e tabelas)."""
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, dict):
        return {k: mask_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(mask_value(v) for v in value)
    return value


class _MaskedStream:
    """Embrulha stdout/stderr: tudo o que vai para a tela passa pelo mask_text."""

    def __init__(self, inner):
        self._inner = inner

    def write(self, s):
        return self._inner.write(mask_text(s) if isinstance(s, str) else s)

    def __getattr__(self, name):
        return getattr(self._inner, name)
