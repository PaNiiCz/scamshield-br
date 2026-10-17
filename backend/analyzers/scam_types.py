"""Classificador do TIPO de golpe.

Dá uma pontuação a cada tipo com base no texto e nos sinais já
encontrados, e escolhe o mais provável. Em caso de empate, vence o tipo
mais específico (o PIX é o mais genérico, por isso fica por último).
"""

import re

from backend.analyzers.rules import normalizar
from backend.core.models import Sinal, TipoGolpe

# Ordem de prioridade no desempate (do mais específico ao mais genérico).
_PRIORIDADE = (
    TipoGolpe.FALSO_PARENTE,
    TipoGolpe.FALSA_OPERADORA,
    TipoGolpe.BOLETO,
    TipoGolpe.CONTA_BLOQUEADA,
    TipoGolpe.PIX,
)

_PONTUACAO_MINIMA = 2

NOMES_AMIGAVEIS = {
    TipoGolpe.BOLETO: "boleto falso",
    TipoGolpe.PIX: "pedido de PIX",
    TipoGolpe.FALSO_PARENTE: "falso parente com número novo",
    TipoGolpe.FALSA_OPERADORA: "falsa operadora",
    TipoGolpe.CONTA_BLOQUEADA: "conta bloqueada",
}


def _pontuar(texto: str, codigos: set[str]) -> dict[TipoGolpe, int]:
    pontos = {tipo: 0 for tipo in _PRIORIDADE}

    # Falso parente
    if "falso_parente" in codigos:
        pontos[TipoGolpe.FALSO_PARENTE] += 3
    if "emergencia_familiar" in codigos:
        pontos[TipoGolpe.FALSO_PARENTE] += 1

    # Falsa operadora
    if re.search(r"\b(?:claro|vivo|tim)\b|\boperadora\b", texto):
        pontos[TipoGolpe.FALSA_OPERADORA] += 2
    if re.search(r"\b(?:sua linha|seu chip|seu plano|recarga)\b", texto):
        pontos[TipoGolpe.FALSA_OPERADORA] += 1
    if "cobranca_pendente" in codigos:
        pontos[TipoGolpe.FALSA_OPERADORA] += 1

    # Boleto
    if re.search(r"\bboleto\b", texto):
        pontos[TipoGolpe.BOLETO] += 2
    if re.search(r"\blinha digitavel\b|\bcodigo de barras\b", texto):
        pontos[TipoGolpe.BOLETO] += 2
    if re.search(r"\bsegunda via\b", texto):
        pontos[TipoGolpe.BOLETO] += 1
    if "cobranca_pendente" in codigos:
        pontos[TipoGolpe.BOLETO] += 1

    # Conta bloqueada
    if "ameaca_bloqueio" in codigos:
        pontos[TipoGolpe.CONTA_BLOQUEADA] += 2
    if re.search(
        r"\b(?:conta|cartao|cpf|acesso|cadastro)\b.{0,30}"
        r"\b(?:bloquead|suspens|irregular|cancelad)",
        texto,
    ):
        pontos[TipoGolpe.CONTA_BLOQUEADA] += 2

    # PIX
    if "pedido_pix" in codigos:
        pontos[TipoGolpe.PIX] += 2
    if re.search(r"\bchave pix\b", texto):
        pontos[TipoGolpe.PIX] += 1
    if "pagamento_antecipado" in codigos:
        pontos[TipoGolpe.PIX] += 1

    return pontos


def classificar_tipo(texto: str, sinais: list[Sinal]) -> TipoGolpe | None:
    """Devolve o tipo mais provável de golpe.

    - None  : nenhum sinal encontrado (não há o que classificar)
    - OUTRO : há sinais, mas nenhum tipo conhecido se destacou
    """
    if not sinais:
        return None

    pontos = _pontuar(normalizar(texto), {s.codigo for s in sinais})
    melhor = max(_PRIORIDADE, key=lambda tipo: pontos[tipo])  # empate: vence o 1º da lista

    if pontos[melhor] < _PONTUACAO_MINIMA:
        return TipoGolpe.OUTRO
    return melhor