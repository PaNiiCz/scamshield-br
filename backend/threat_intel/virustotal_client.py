"""Cliente do VirusTotal (Etapa 9). Consulta passiva: só PERGUNTA, nunca envia.

Regras deste módulo:
- só o DOMÍNIO (ou o SHA-256 de um arquivo) sai da máquina, nunca o link
  inteiro, o texto da mensagem ou o conteúdo de um arquivo;
- só usamos GET ("vocês conhecem isto?"). Nunca POST: enviar um link ou
  arquivo para análise o tornaria acessível a outras pessoas;
- "desconhecido" (404) NÃO significa "seguro": só deixa de gerar sinal;
- a chave vem do .env e nunca aparece em mensagens de erro nem em log;
- plano gratuito: 4 consultas por minuto e 500 por dia. O limite é
  controlado AQUI, porque a API não manda cabeçalhos de limite.

Atenção: os termos do plano gratuito proíbem uso em produto ou serviço
comercial. Para uso comercial é preciso um plano pago do VirusTotal.
"""

import logging
import re
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Callable

import httpx

from backend.core.config import get_settings
from backend.core.errors import ServicoExternoError
from backend.core.models import Sinal
from backend.osint.cache import CacheTTL
from backend.osint.http_client import criar_cliente
from backend.osint.osint_service import selecionar_dominios
from backend.osint.validacao import validar_dominio

logger = logging.getLogger(__name__)

BASE = "https://www.virustotal.com/api/v3"
ORIGEM = "virustotal"
VALIDADE_CACHE_SEGUNDOS = 6 * 3600
MAX_DOMINIOS_POR_ANALISE = 2
LIMITE_POR_MINUTO = 4
LIMITE_POR_DIA = 400  # folga abaixo dos 500 do plano gratuito

# Quantos motores precisam marcar para virar sinal. Um único motor marcando é
# comum até em sites gigantes (google.com tem 1 de 92), então não conta.
MINIMO_PARA_SINAL = 3
LIMITE_MEDIO = 6
LIMITE_ALTO = 10

_RE_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ReputacaoVT:
    """Contagem de motores de segurança que deram veredito (ignora timeout/falha)."""

    malicioso: int = 0
    suspeito: int = 0
    inofensivo: int = 0
    nao_detectado: int = 0

    @property
    def marcados(self) -> int:
        return self.malicioso + self.suspeito

    @property
    def total(self) -> int:
        return self.malicioso + self.suspeito + self.inofensivo + self.nao_detectado


# --- Limite de consultas ----------------------------------------------------------


class LimitadorVT:
    """Garante no máximo N consultas por minuto e M por dia (vale para todas as threads)."""

    def __init__(
        self,
        por_minuto: int = LIMITE_POR_MINUTO,
        por_dia: int = LIMITE_POR_DIA,
        relogio: Callable[[], float] = time.monotonic,
        hoje: Callable[[], date] = lambda: datetime.now(timezone.utc).date(),
    ):
        self._por_minuto = por_minuto
        self._por_dia = por_dia
        self._relogio = relogio
        self._hoje = hoje
        self._trava = threading.Lock()
        self._usos: deque[float] = deque()
        self._dia = hoje()
        self._usos_no_dia = 0

    def tentar_usar(self) -> bool:
        with self._trava:
            agora = self._relogio()
            while self._usos and agora - self._usos[0] >= 60:
                self._usos.popleft()
            hoje = self._hoje()
            if hoje != self._dia:
                self._dia, self._usos_no_dia = hoje, 0
            if len(self._usos) >= self._por_minuto or self._usos_no_dia >= self._por_dia:
                return False
            self._usos.append(agora)
            self._usos_no_dia += 1
            return True


_limitador = LimitadorVT()
_cache_dominio = CacheTTL(VALIDADE_CACHE_SEGUNDOS)
_cache_arquivo = CacheTTL(VALIDADE_CACHE_SEGUNDOS)


def limpar_estado() -> None:
    """Zera cache e contadores (usado pelos testes)."""
    global _limitador
    _limitador = LimitadorVT()
    _cache_dominio.limpar()
    _cache_arquivo.limpar()


# --- Consultas ----------------------------------------------------------------------


def _numero(valor: object) -> int:
    return valor if isinstance(valor, int) and not isinstance(valor, bool) and valor >= 0 else 0


def _pedir(cliente: httpx.Client, caminho: str, chave: str) -> dict | None:
    try:
        resposta = cliente.get(
            BASE + caminho, headers={"x-apikey": chave, "accept": "application/json"}
        )
    except httpx.HTTPError as erro:
        raise ServicoExternoError("VirusTotal indisponível no momento.") from erro
    if resposta.status_code == 404:
        return None  # desconhecido
    if resposta.status_code in (401, 403):
        raise ServicoExternoError("O VirusTotal recusou a chave de API. Confira VIRUSTOTAL_API_KEY no .env.")
    if resposta.status_code == 429:
        raise ServicoExternoError("Limite de consultas do VirusTotal atingido. Tente mais tarde.")
    if resposta.status_code != 200:
        raise ServicoExternoError(f"VirusTotal respondeu com status {resposta.status_code}.")
    try:
        dados = resposta.json()
    except ValueError as erro:
        raise ServicoExternoError("VirusTotal devolveu uma resposta ilegível.") from erro
    if not isinstance(dados, dict):
        raise ServicoExternoError("VirusTotal devolveu uma resposta inesperada.")
    return dados


def _ler_reputacao(dados: dict | None) -> ReputacaoVT | None:
    if dados is None:
        return None
    corpo = dados.get("data")
    atributos = corpo.get("attributes") if isinstance(corpo, dict) else None
    estatisticas = atributos.get("last_analysis_stats") if isinstance(atributos, dict) else None
    if not isinstance(estatisticas, dict):
        return None
    return ReputacaoVT(
        malicioso=_numero(estatisticas.get("malicious")),
        suspeito=_numero(estatisticas.get("suspicious")),
        inofensivo=_numero(estatisticas.get("harmless")),
        nao_detectado=_numero(estatisticas.get("undetected")),
    )


def consultar_dominio(dominio: str, chave: str, cliente: httpx.Client) -> ReputacaoVT | None:
    """Reputação do domínio, ou None se o VirusTotal não o conhece."""
    dominio = validar_dominio(dominio)
    return _ler_reputacao(_pedir(cliente, f"/domains/{dominio}", chave))


def consultar_arquivo(sha256: str, chave: str, cliente: httpx.Client) -> ReputacaoVT | None:
    """Reputação do arquivo pelo SHA-256, ou None se o VirusTotal não o conhece."""
    sha256 = (sha256 or "").strip().lower()
    if not _RE_SHA256.match(sha256):
        raise ServicoExternoError("Hash SHA-256 inválido para consulta.")
    return _ler_reputacao(_pedir(cliente, f"/files/{sha256}", chave))


def reservar_consulta() -> bool:
    """Pede uma "vaga" no limite local de consultas."""
    return _limitador.tentar_usar()


def reputacao_do_dominio(dominio: str, chave: str, cliente: httpx.Client) -> ReputacaoVT | None:
    """Como consultar_dominio, mas com cache e limite local de consultas."""
    dominio = validar_dominio(dominio)
    achou, valor = _cache_dominio.buscar(dominio)
    if achou:
        return valor
    if not reservar_consulta():
        raise ServicoExternoError("Limite local de consultas ao VirusTotal atingido.")
    valor = consultar_dominio(dominio, chave, cliente)
    _cache_dominio.guardar(dominio, valor)
    return valor


def reputacao_do_arquivo(sha256: str, chave: str, cliente: httpx.Client) -> ReputacaoVT | None:
    """Como consultar_arquivo, mas com cache e limite local de consultas."""
    sha256 = (sha256 or "").strip().lower()
    achou, valor = _cache_arquivo.buscar(sha256)
    if achou:
        return valor
    if not reservar_consulta():
        raise ServicoExternoError("Limite local de consultas ao VirusTotal atingido.")
    valor = consultar_arquivo(sha256, chave, cliente)
    _cache_arquivo.guardar(sha256, valor)
    return valor


# --- Sinal de domínio ----------------------------------------------------------------


def sinal_de_dominio(dominio: str, reputacao: ReputacaoVT) -> Sinal | None:
    marcados = reputacao.marcados
    if marcados < MINIMO_PARA_SINAL or reputacao.total == 0:
        return None
    if marcados >= LIMITE_ALTO:
        pontos, forte = 45, True
    elif marcados >= LIMITE_MEDIO:
        pontos, forte = 30, False
    else:
        pontos, forte = 15, False
    return Sinal(
        codigo="virustotal_malicioso",
        descricao=(
            f"{marcados} de {reputacao.total} motores de segurança do VirusTotal marcam o "
            f"domínio {dominio} como perigoso ou suspeito. É uma estimativa de terceiros, "
            "não uma certeza."
        ),
        pontos=pontos,
        origem=ORIGEM,
        forte=forte,
    )


def _tarefa_dominio(dominio: str, chave: str, cliente: httpx.Client) -> Sinal | None:
    """Roda uma consulta; nenhuma falha sai daqui. Não registramos domínio nem chave no log."""
    try:
        reputacao = reputacao_do_dominio(dominio, chave, cliente)
        return sinal_de_dominio(dominio, reputacao) if reputacao else None
    except ServicoExternoError as erro:
        logger.info("VirusTotal: indisponível (%s)", erro.mensagem)
    except Exception as erro:  # noqa: BLE001 - nada aqui pode derrubar a análise
        logger.warning("VirusTotal: erro inesperado (%s)", type(erro).__name__)
    return None


def analisar_virustotal(texto: str) -> list[Sinal]:
    """Sinais do VirusTotal para os links do texto. Vazio se estiver desligado."""
    config = get_settings()
    chave = config.virustotal_api_key.strip()
    if not chave or not config.osint_ativado:
        return []
    dominios = selecionar_dominios(texto, MAX_DOMINIOS_POR_ANALISE)
    if not dominios:
        return []

    cliente = criar_cliente(config.osint_timeout_segundos)
    executor = ThreadPoolExecutor(max_workers=len(dominios))
    try:
        futuros = [executor.submit(_tarefa_dominio, d, chave, cliente) for d in dominios]
        wait(futuros, timeout=config.osint_timeout_segundos + 1.0)
        melhor: Sinal | None = None
        for futuro in futuros:
            if futuro.done() and not futuro.cancelled():
                sinal = futuro.result()
                if sinal and (melhor is None or sinal.pontos > melhor.pontos):
                    melhor = sinal
        return [melhor] if melhor else []
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        cliente.close()