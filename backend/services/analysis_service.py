"""Orquestrador da análise.

Recebe a mensagem, chama os analisadores adequados, entrega os sinais
ao motor de risco e monta o resultado final.

Analisadores ativos: regras (Etapa 3) e URLs (Etapa 5). Nas próximas
etapas, os demais (ML, e-mail, OSINT...) entram na lista de sinais aqui.
"""

from backend.analyzers.rules import analisar_regras
from backend.analyzers.scam_types import NOMES_AMIGAVEIS, classificar_tipo
from backend.analyzers.url_analyzer import analisar_urls
from backend.core.models import (
    MensagemEntrada,
    NivelRisco,
    ResultadoAnalise,
    Sinal,
    TipoGolpe,
)
from backend.risk.risk_engine import calcular_risco


def _montar_resumo(
    nivel: NivelRisco,
    qtd_sinais: int,
    motivo: str | None,
    tipo: TipoGolpe | None,
) -> str:
    sinais = "sinal" if qtd_sinais == 1 else "sinais"

    if nivel == NivelRisco.VERDE:
        resumo = (
            "Não encontramos sinais fortes de golpe nesta mensagem. "
            "Isso não garante que ela seja segura: na dúvida, confirme "
            "pelo canal oficial da empresa."
        )
    elif nivel == NivelRisco.LARANJA:
        resumo = (
            f"Mensagem suspeita: encontramos {qtd_sinais} {sinais} de golpe. "
            "Não responda, não clique em links e confirme pelo canal oficial."
        )
    else:
        resumo = (
            f"Alto risco: encontramos {qtd_sinais} {sinais} de golpe. "
            "Não pague, não envie dados e não clique em links. "
            "Confirme pelo canal oficial da empresa."
        )

    if tipo in NOMES_AMIGAVEIS:
        resumo += f" Tipo provável: {NOMES_AMIGAVEIS[tipo]}."
    if motivo:
        resumo += f" Nível mínimo aplicado por regra de segurança: {motivo}."
    return resumo


def analisar_mensagem(mensagem: MensagemEntrada) -> ResultadoAnalise:
    """Analisa uma mensagem e devolve o resultado explicável."""
    sinais: list[Sinal] = []

    sinais.extend(analisar_regras(mensagem.texto))
    sinais.extend(analisar_urls(mensagem.texto))

    # Sinais mais pesados primeiro: o usuário vê o que mais importa no topo.
    sinais.sort(key=lambda s: s.pontos, reverse=True)

    veredito = calcular_risco(sinais)

    # Só classificamos o tipo quando há motivo para desconfiar.
    tipo = None
    if veredito.nivel != NivelRisco.VERDE:
        tipo = classificar_tipo(mensagem.texto, sinais)

    return ResultadoAnalise(
        pontuacao=veredito.pontuacao,
        nivel=veredito.nivel,
        sinais=sinais,
        tipo_golpe=tipo,
        resumo=_montar_resumo(
            veredito.nivel, len(sinais), veredito.motivo_forcado, tipo
        ),
    )