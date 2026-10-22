"""Rede do domínio (Etapa 8, parte 3): onde o site está hospedado e a quem denunciar.

Passos, todos passivos (nunca conectamos ao IP investigado):
1. DNS-over-HTTPS (Cloudflare, com Google de reserva): domínio -> IPs.
2. RIPEstat: IP -> número do ASN e nome da operadora.
3. RDAP de IP (via rdap.org): nome da rede e e-mail de abuso.

Esses dados NÃO viram sinais de risco: servem para montar a denúncia
(Etapa 10). Por isso a análise normal (/analisar) não chama este módulo.
Atenção: se o site usa CDN (Cloudflare, Amazon CloudFront...), o IP e o
contato de abuso são da CDN, e é a ela mesmo que se denuncia.
"""

import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from backend.core.config import get_settings
from backend.core.errors import ServicoExternoError
from backend.osint.cache import CacheTTL
from backend.osint.http_client import criar_cliente
from backend.osint.validacao import validar_dominio

logger = logging.getLogger(__name__)

VALIDADE_CACHE_SEGUNDOS = 3600
MAX_IPS = 4

_SERVIDORES_DOH = (
    ("https://cloudflare-dns.com/dns-query", {"accept": "application/dns-json"}),
    ("https://dns.google/resolve", {}),
)
URL_RIPESTAT = "https://stat.ripe.net/data/prefix-overview/data.json"
URL_RDAP_IP = "https://rdap.org/ip/"

_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

_cache_rede = CacheTTL(VALIDADE_CACHE_SEGUNDOS)


def limpar_cache() -> None:
    _cache_rede.limpar()


@dataclass(frozen=True)
class InfoRede:
    """O que descobrimos sobre a hospedagem do domínio. Campos vazios = não sabemos."""

    dominio: str
    ips: tuple[str, ...] = ()
    asn: int | None = None
    asn_titular: str | None = None
    prefixo: str | None = None
    rede_nome: str | None = None
    emails_abuso: tuple[str, ...] = ()


def _validar_ip_publico(ip: str) -> str:
    """Só IPs públicos: o texto vem de terceiros e nunca vira consulta sem conferir."""
    try:
        objeto = ipaddress.ip_address((ip or "").strip())
    except ValueError as erro:
        raise ServicoExternoError("IP inválido para consulta.") from erro
    if not objeto.is_global:
        raise ServicoExternoError("IP não público: consulta recusada.")
    return str(objeto)


def _pegar_json(cliente: httpx.Client, url: str, nome_servico: str, **kwargs) -> Any:
    try:
        resposta = cliente.get(url, **kwargs)
    except httpx.HTTPError as erro:
        raise ServicoExternoError(f"{nome_servico} indisponível no momento.") from erro
    if resposta.status_code == 404:
        return None
    if resposta.status_code != 200:
        raise ServicoExternoError(f"{nome_servico} respondeu com status {resposta.status_code}.")
    try:
        return resposta.json()
    except ValueError as erro:
        raise ServicoExternoError(f"{nome_servico} devolveu uma resposta ilegível.") from erro


# --- 1. DNS -------------------------------------------------------------------


def _resolver_em(url: str, cabecalhos: dict, dominio: str, cliente: httpx.Client) -> list[str]:
    dados = _pegar_json(
        cliente, url, "DNS", params={"name": dominio, "type": "A"}, headers=cabecalhos
    )
    if not isinstance(dados, dict) or dados.get("Status") != 0:
        return []  # Status 3 = domínio não existe
    respostas = dados.get("Answer")
    if not isinstance(respostas, list):
        return []
    ips: list[str] = []
    for item in respostas:
        # type 1 = endereço IPv4; type 5 = CNAME (apelido), que ignoramos
        if not isinstance(item, dict) or item.get("type") != 1:
            continue
        valor = item.get("data")
        if not isinstance(valor, str):
            continue
        try:
            ip = ipaddress.ip_address(valor.strip())
        except ValueError:
            continue
        if ip.version != 4 or not ip.is_global:
            continue
        texto = str(ip)
        if texto not in ips:
            ips.append(texto)
        if len(ips) >= MAX_IPS:
            break
    return ips


def resolver_dominio(dominio: str, cliente: httpx.Client) -> list[str]:
    """IPs públicos (IPv4) do domínio. Lista vazia se o domínio não existe."""
    dominio = validar_dominio(dominio)
    ultimo_erro: ServicoExternoError | None = None
    for url, cabecalhos in _SERVIDORES_DOH:
        try:
            return _resolver_em(url, cabecalhos, dominio, cliente)
        except ServicoExternoError as erro:
            ultimo_erro = erro
    raise ultimo_erro or ServicoExternoError("DNS indisponível no momento.")


# --- 2. ASN -------------------------------------------------------------------


def consultar_asn(ip: str, cliente: httpx.Client) -> tuple[int | None, str | None, str | None]:
    """(número do ASN, nome da operadora, prefixo) do IP, com None onde não souber."""
    ip = _validar_ip_publico(ip)
    dados = _pegar_json(cliente, URL_RIPESTAT, "RIPEstat", params={"resource": ip})
    if not isinstance(dados, dict) or dados.get("status") != "ok":
        return None, None, None
    corpo = dados.get("data")
    if not isinstance(corpo, dict):
        return None, None, None

    prefixo = None
    bruto = corpo.get("resource")
    if isinstance(bruto, str) and len(bruto) <= 64:
        try:
            prefixo = str(ipaddress.ip_network(bruto, strict=False))
        except ValueError:
            prefixo = None

    asns = corpo.get("asns")
    if isinstance(asns, list):
        for item in asns:
            if not isinstance(item, dict):
                continue
            numero = item.get("asn")
            if isinstance(numero, int) and not isinstance(numero, bool):
                titular = item.get("holder")
                titular = titular[:200] if isinstance(titular, str) else None
                return numero, titular, prefixo
    return None, None, prefixo


# --- 3. RDAP de IP ------------------------------------------------------------


def _emails_de_abuso(entidades: Any, achados: list[str]) -> None:
    if not isinstance(entidades, list):
        return
    for entidade in entidades:
        if not isinstance(entidade, dict):
            continue
        papeis = entidade.get("roles")
        if isinstance(papeis, list) and "abuse" in papeis:
            vcard = entidade.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for campo in vcard[1]:
                    if (
                        isinstance(campo, list)
                        and len(campo) >= 4
                        and campo[0] == "email"
                        and isinstance(campo[3], str)
                    ):
                        email = campo[3].strip()
                        if len(email) <= 254 and _RE_EMAIL.match(email) and email not in achados:
                            achados.append(email)
        _emails_de_abuso(entidade.get("entities"), achados)  # contatos ficam aninhados


def consultar_abuso(ip: str, cliente: httpx.Client) -> tuple[str | None, tuple[str, ...]]:
    """(nome da rede, e-mails de abuso) segundo o RDAP do IP."""
    ip = _validar_ip_publico(ip)
    dados = _pegar_json(cliente, URL_RDAP_IP + ip, "RDAP de IP")
    if not isinstance(dados, dict):
        return None, ()
    nome = dados.get("name")
    nome = nome[:200] if isinstance(nome, str) else None
    emails: list[str] = []
    _emails_de_abuso(dados.get("entities"), emails)
    return nome, tuple(emails)


# --- Orquestração -------------------------------------------------------------


def _seguro(funcao: Callable[..., Any], *args: Any) -> Any:
    """Roda uma consulta; qualquer falha vira None. Não registramos domínio nem IP no log."""
    try:
        return funcao(*args)
    except ServicoExternoError as erro:
        logger.info("Rede: fonte indisponível (%s)", erro.mensagem)
    except Exception as erro:  # noqa: BLE001 - nada aqui pode derrubar o sistema
        logger.warning("Rede: erro inesperado (%s)", type(erro).__name__)
    return None


def investigar_rede(dominio: str) -> InfoRede:
    """Descobre IP, ASN e contato de abuso do domínio. Nunca levanta erro.

    Devolve um InfoRede com campos vazios onde algo falhou, ou se o OSINT
    estiver desligado. Só o domínio (no DNS) e o IP (nas demais consultas)
    saem da máquina.
    """
    dominio = (dominio or "").strip().lower()
    vazio = InfoRede(dominio=dominio)
    config = get_settings()
    if not config.osint_ativado:
        return vazio
    try:
        dominio = validar_dominio(dominio)
    except ServicoExternoError:
        return vazio
    vazio = InfoRede(dominio=dominio)

    achou, guardado = _cache_rede.buscar(dominio)
    if achou:
        return guardado

    cliente = criar_cliente(config.osint_timeout_segundos)
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        ips = _seguro(resolver_dominio, dominio, cliente) or []
        if not ips:
            return vazio
        ip = ips[0]  # com CDN todos os IPs são da mesma operadora; basta o primeiro

        futuro_asn = executor.submit(_seguro, consultar_asn, ip, cliente)
        futuro_abuso = executor.submit(_seguro, consultar_abuso, ip, cliente)
        wait([futuro_asn, futuro_abuso], timeout=config.osint_timeout_segundos + 1.0)

        asn, titular, prefixo = (None, None, None)
        if futuro_asn.done() and futuro_asn.result() is not None:
            asn, titular, prefixo = futuro_asn.result()
        nome_rede, emails = (None, ())
        if futuro_abuso.done() and futuro_abuso.result() is not None:
            nome_rede, emails = futuro_abuso.result()

        info = InfoRede(
            dominio=dominio,
            ips=tuple(ips),
            asn=asn,
            asn_titular=titular,
            prefixo=prefixo,
            rede_nome=nome_rede,
            emails_abuso=emails,
        )
        # Só guardamos resultado completo: falha passageira não deve ficar 1 hora no cache.
        if asn is not None and emails:
            _cache_rede.guardar(dominio, info)
        return info
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        cliente.close()