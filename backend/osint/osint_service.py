"""Orquestrador do OSINT passivo (Etapa 8).

Escolhe os domínios dos links, consulta as fontes públicas em paralelo,
com cache e limite de tempo, e devolve sinais. Qualquer falha de fonte
externa só faz o sinal correspondente não aparecer: a análise continua.
"""

import ipaddress
import logging
from concurrent.futures import Future, ThreadPoolExecutor, wait
from datetime import datetime
from typing import Callable
from urllib.parse import urlparse

import httpx

from backend.analyzers.url_analyzer import (
    ENCURTADORES,
    dominio_registrado,
    e_oficial,
    extrair_urls,
)
from backend.core.config import get_settings
from backend.core.errors import ServicoExternoError
from backend.core.models import Sinal
from backend.osint.cache import CacheTTL
from backend.osint.domain_lookup import analisar_idade_dominio, consultar_data_registro
from backend.osint.http_client import criar_cliente
from backend.osint.site_history import analisar_historico, tem_historico

logger = logging.getLogger(__name__)

VALIDADE_CACHE_SEGUNDOS = 3600  # 1 hora

_cache_registro = CacheTTL(VALIDADE_CACHE_SEGUNDOS)
_cache_historico = CacheTTL(VALIDADE_CACHE_SEGUNDOS)


def limpar_cache() -> None:
    _cache_registro.limpar()
    _cache_historico.limpar()


def _host_da_url(url: str) -> str | None:
    try:
        host = urlparse(url if "://" in url else "http://" + url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _e_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def selecionar_dominios(texto: str, maximo: int) -> list[str]:
    """Domínios registrados dos links que valem uma consulta (até `maximo`).

    Ficam de fora: IPs (nada a consultar no RDAP), domínios oficiais
    conhecidos, encurtadores (o RDAP deles não diz nada sobre o destino)
    e nomes sem sufixo válido (localhost, nomes internos).
    """
    escolhidos: list[str] = []
    for url in extrair_urls(texto):
        host = _host_da_url(url)
        if not host or _e_ip(host) or e_oficial(host) or host in ENCURTADORES:
            continue
        dominio = dominio_registrado(host).lower()
        if "." not in dominio or dominio in ENCURTADORES or dominio in escolhidos:
            continue
        escolhidos.append(dominio)
        if len(escolhidos) >= maximo:
            break
    return escolhidos


def _data_de_registro(dominio: str, cliente: httpx.Client) -> datetime | None:
    achou, valor = _cache_registro.buscar(dominio)
    if achou:
        return valor
    valor = consultar_data_registro(dominio, cliente)
    _cache_registro.guardar(dominio, valor)
    return valor


def _historico(dominio: str, cliente: httpx.Client) -> bool | None:
    achou, valor = _cache_historico.buscar(dominio)
    if achou:
        return valor
    valor = tem_historico(dominio, cliente)
    _cache_historico.guardar(dominio, valor)
    return valor


def _tarefa_idade(dominio: str, cliente: httpx.Client) -> Sinal | None:
    return analisar_idade_dominio(dominio, _data_de_registro(dominio, cliente))


def _tarefa_historico(dominio: str, cliente: httpx.Client) -> Sinal | None:
    return analisar_historico(dominio, _historico(dominio, cliente))


def _executar_seguro(
    tarefa: Callable[[str, httpx.Client], Sinal | None],
    dominio: str,
    cliente: httpx.Client,
) -> Sinal | None:
    """Roda uma consulta; nenhuma falha sai daqui. Não registramos o domínio no log."""
    try:
        return tarefa(dominio, cliente)
    except ServicoExternoError as erro:
        logger.info("OSINT: fonte indisponível (%s)", erro.mensagem)
    except Exception as erro:  # noqa: BLE001 - nada aqui pode derrubar a análise
        logger.warning("OSINT: erro inesperado (%s)", type(erro).__name__)
    return None


def analisar_osint(texto: str) -> list[Sinal]:
    """Sinais de OSINT para os links do texto. Lista vazia se desligado."""
    config = get_settings()
    if not config.osint_ativado:
        return []

    dominios = selecionar_dominios(texto, config.osint_max_dominios)
    if not dominios:
        return []

    cliente = criar_cliente(config.osint_timeout_segundos)
    executor = ThreadPoolExecutor(max_workers=len(dominios) * 2)
    try:
        futuros: list[Future[Sinal | None]] = []
        for dominio in dominios:
            for tarefa in (_tarefa_idade, _tarefa_historico):
                futuros.append(executor.submit(_executar_seguro, tarefa, dominio, cliente))

        # Orçamento total de tempo: quem não terminou é ignorado.
        wait(futuros, timeout=config.osint_timeout_segundos + 1.0)

        por_codigo: dict[str, Sinal] = {}
        for futuro in futuros:
            if not futuro.done() or futuro.cancelled():
                continue
            sinal = futuro.result()
            if sinal is None:
                continue
            atual = por_codigo.get(sinal.codigo)
            if atual is None or sinal.pontos > atual.pontos:
                por_codigo[sinal.codigo] = sinal
        return list(por_codigo.values())
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        cliente.close()