"""Análise de arquivo pelo hash (Etapa 9). O arquivo NUNCA é aberto nem executado.

O que fazemos: lemos os bytes recebidos em pedaços, calculamos o SHA-256
(a "impressão digital" do arquivo) e perguntamos ao VirusTotal se ele
conhece esse código. Nada é gravado em disco, o conteúdo nunca é enviado
a ninguém e a resposta nunca o repete.

"O VirusTotal não conhece este arquivo" NÃO significa "arquivo seguro".
"""

import hashlib

from pydantic import BaseModel

from backend.core.config import get_settings
from backend.core.errors import EntradaInvalidaError, ServicoExternoError
from backend.core.models import NivelRisco, Sinal
from backend.risk.risk_engine import calcular_risco
from backend.threat_intel import virustotal_client as vt
from backend.threat_intel.virustotal_client import ReputacaoVT

LIMITE_BYTES = 25 * 1024 * 1024  # 25 MB


class ArquivoGrandeDemaisError(EntradaInvalidaError):
    """O arquivo passou do tamanho máximo aceito."""


class ResultadoArquivo(BaseModel):
    sha256: str
    tamanho_bytes: int
    virustotal_consultado: bool
    conhecido_no_virustotal: bool | None
    motores_marcaram: int | None
    motores_total: int | None
    pontuacao: int
    nivel: NivelRisco
    sinais: list[Sinal]
    resumo: str


class CalculadoraHash:
    """Calcula o SHA-256 aos poucos, sem guardar o arquivo na memória nem no disco."""

    def __init__(self, limite: int | None = None):
        self._limite = LIMITE_BYTES if limite is None else limite
        self._hash = hashlib.sha256()
        self._tamanho = 0

    def adicionar(self, pedaco: bytes) -> None:
        self._tamanho += len(pedaco)
        if self._tamanho > self._limite:
            raise ArquivoGrandeDemaisError("O arquivo é maior que o tamanho máximo aceito.")
        self._hash.update(pedaco)

    def resultado(self) -> tuple[str, int]:
        return self._hash.hexdigest(), self._tamanho


def sinal_de_arquivo(reputacao: ReputacaoVT) -> Sinal | None:
    marcados = reputacao.marcados
    if marcados < vt.MINIMO_PARA_SINAL or reputacao.total == 0:
        return None
    forte = marcados >= vt.LIMITE_ALTO
    return Sinal(
        codigo="arquivo_malicioso",
        descricao=(
            f"{marcados} de {reputacao.total} motores de segurança do VirusTotal marcam este "
            "arquivo como perigoso ou suspeito. É uma estimativa de terceiros, não uma certeza."
        ),
        pontos=60 if forte else 30,
        origem=vt.ORIGEM,
        forte=forte,
    )


def _resumo(consultado: bool, conhecido: bool | None, rep: ReputacaoVT | None, nivel: NivelRisco) -> str:
    if not consultado:
        return (
            "Não foi possível consultar o VirusTotal agora (sem chave, desligado ou fora do ar). "
            "Guarde o código SHA-256 e consulte o arquivo em virustotal.com antes de abri-lo."
        )
    if not conhecido:
        return (
            "O VirusTotal não conhece este arquivo. Isso NÃO significa que ele seja seguro: "
            "arquivos novos ou raros não aparecem lá. Na dúvida, não abra."
        )
    if nivel == NivelRisco.VERDE:
        return (
            f"{rep.marcados} de {rep.total} motores de segurança marcaram este arquivo. "
            "Isso não garante que ele seja seguro: confirme a origem antes de abrir."
        )
    return (
        f"{rep.marcados} de {rep.total} motores de segurança marcaram este arquivo como perigoso "
        "ou suspeito. Não abra, não execute e não encaminhe."
    )


def analisar_hash(sha256: str, tamanho: int, chave: str, cliente) -> ResultadoArquivo:
    """Monta o resultado a partir do hash. Falha do VirusTotal nunca vira erro."""
    consultado = False
    conhecido: bool | None = None
    reputacao: ReputacaoVT | None = None
    sinais: list[Sinal] = []

    if chave:
        try:
            reputacao = vt.reputacao_do_arquivo(sha256, chave, cliente)
            consultado = True
            conhecido = reputacao is not None
            if reputacao is not None:
                sinal = sinal_de_arquivo(reputacao)
                if sinal:
                    sinais.append(sinal)
        except ServicoExternoError:
            consultado, conhecido, reputacao = False, None, None

    veredito = calcular_risco(sinais)
    return ResultadoArquivo(
        sha256=sha256,
        tamanho_bytes=tamanho,
        virustotal_consultado=consultado,
        conhecido_no_virustotal=conhecido,
        motores_marcaram=reputacao.marcados if reputacao else None,
        motores_total=reputacao.total if reputacao else None,
        pontuacao=veredito.pontuacao,
        nivel=veredito.nivel,
        sinais=sinais,
        resumo=_resumo(consultado, conhecido, reputacao, veredito.nivel),
    )


def analisar_hash_do_arquivo(sha256: str, tamanho: int) -> ResultadoArquivo:
    """Versão que lê as configurações (chave e OSINT ligado) e cuida do cliente HTTP."""
    config = get_settings()
    chave = config.virustotal_api_key.strip() if config.osint_ativado else ""
    if not chave:
        return analisar_hash(sha256, tamanho, "", None)
    cliente = vt.criar_cliente(config.osint_timeout_segundos)
    try:
        return analisar_hash(sha256, tamanho, chave, cliente)
    finally:
        cliente.close()