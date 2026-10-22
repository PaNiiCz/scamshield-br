"""Validação do nome de domínio antes de colocá-lo numa URL de consulta."""

import re

from backend.core.errors import ServicoExternoError

# letras, números e hífen; pelo menos um ponto; até 253 caracteres no total
_RE_DOMINIO = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def validar_dominio(nome: str) -> str:
    """Devolve o domínio em minúsculas ou recusa nomes estranhos.

    O texto vem de uma mensagem de golpista: nunca confiamos nele para
    montar um endereço sem conferir (evita "../", espaços, "?", "/" etc.).
    """
    limpo = (nome or "").strip().lower().rstrip(".")
    if not _RE_DOMINIO.match(limpo):
        raise ServicoExternoError("Nome de domínio inválido para consulta.")
    return limpo