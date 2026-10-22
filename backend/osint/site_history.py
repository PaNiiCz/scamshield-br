"""Histórico do site no Archive.org (Wayback Machine). Consulta passiva.

Perguntamos ao Archive.org se ele já guardou alguma cópia do endereço.
Site de golpe costuma ser criado e usado em poucos dias, então muitas
vezes não há nenhum registro. Só o domínio é enviado.
"""

import httpx

from backend.core.errors import ServicoExternoError
from backend.core.models import Sinal
from backend.osint.validacao import validar_dominio

ORIGEM = "osint"
URL_WAYBACK = "https://archive.org/wayback/available"


def tem_historico(dominio: str, cliente: httpx.Client) -> bool | None:
    """True/False se o Archive.org tem (ou não) cópia do domínio; None se o
    formato da resposta for inesperado."""
    dominio = validar_dominio(dominio)
    try:
        resposta = cliente.get(URL_WAYBACK, params={"url": dominio})
    except httpx.HTTPError as erro:
        raise ServicoExternoError("Archive.org indisponível no momento.") from erro
    if resposta.status_code != 200:
        raise ServicoExternoError(f"Archive.org respondeu com status {resposta.status_code}.")
    try:
        dados = resposta.json()
    except ValueError as erro:
        raise ServicoExternoError("Archive.org devolveu uma resposta ilegível.") from erro

    if not isinstance(dados, dict):
        return None
    copias = dados.get("archived_snapshots")
    if not isinstance(copias, dict):
        return None
    proxima = copias.get("closest")
    if not isinstance(proxima, dict):
        return False
    return bool(proxima.get("available"))


def analisar_historico(dominio: str, tem: bool | None) -> Sinal | None:
    """Sinal 'site_sem_historico' (10 pontos) só quando SABEMOS que não há cópia."""
    if tem is not False:
        return None
    return Sinal(
        codigo="site_sem_historico",
        descricao=(
            f"Não encontramos nenhuma cópia antiga de {dominio} no Archive.org. "
            "Sites de golpe costumam ser criados e usados em pouco tempo."
        ),
        pontos=10,
        origem=ORIGEM,
        forte=False,
    )