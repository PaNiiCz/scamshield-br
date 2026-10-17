"""Motor de risco do ScamShield BR.

Recebe os sinais encontrados pelos analisadores e decide:
  - a pontuação (0 a 100)
  - o nível (verde, laranja, vermelho)

Regras de segurança contra falso negativo: sinais fortes e certas
combinações de sinais forçam no mínimo o nível laranja, não importa
quanto a soma dê.
"""

from dataclasses import dataclass

from backend.core.config import Settings, get_settings
from backend.core.models import NivelRisco, Sinal

# Combinações de sinais que, juntas, já justificam no mínimo o nível laranja.
# (O sinal "dominio_imitando_marca" será criado pelo url_analyzer, na Etapa 5.)
COMBINACOES_FORCAM_LARANJA: tuple[tuple[frozenset[str], str], ...] = (
    (
        frozenset({"pedido_pix", "urgencia_falsa", "dominio_imitando_marca"}),
        "PIX + urgência + domínio imitando marca conhecida",
    ),
    (
        frozenset({"pedido_pix", "ameaca_bloqueio"}),
        "pedido de PIX combinado com ameaça de bloqueio",
    ),
    (
        frozenset({"falso_parente", "pedido_pix"}),
        "roteiro de parente com número novo pedindo PIX",
    ),
)


@dataclass(frozen=True)
class Veredito:
    pontuacao: int
    nivel: NivelRisco
    # Se o nível foi elevado por uma regra de segurança, o motivo fica aqui.
    motivo_forcado: str | None = None


def _nivel_por_pontuacao(pontuacao: int, config: Settings) -> NivelRisco:
    if pontuacao >= config.limiar_alto_risco:
        return NivelRisco.VERMELHO
    if pontuacao >= config.limiar_suspeito:
        return NivelRisco.LARANJA
    return NivelRisco.VERDE


def _motivo_para_forcar_laranja(sinais: list[Sinal]) -> str | None:
    """Devolve o motivo se alguma regra de segurança se aplica, senão None."""
    for sinal in sinais:
        if sinal.forte:
            return f"sinal forte encontrado ({sinal.codigo})"

    codigos = {sinal.codigo for sinal in sinais}
    for combinacao, descricao in COMBINACOES_FORCAM_LARANJA:
        if combinacao <= codigos:  # "<=" em conjuntos = "está contido em"
            return descricao
    return None


def calcular_risco(
    sinais: list[Sinal], config: Settings | None = None
) -> Veredito:
    """Soma os sinais e aplica as regras de segurança."""
    config = config or get_settings()

    pontuacao = min(100, sum(sinal.pontos for sinal in sinais))
    nivel = _nivel_por_pontuacao(pontuacao, config)
    motivo: str | None = None

    # Só faz sentido forçar quando o nível calculado ficou abaixo de laranja.
    if nivel == NivelRisco.VERDE:
        motivo = _motivo_para_forcar_laranja(sinais)
        if motivo:
            nivel = NivelRisco.LARANJA
            pontuacao = max(pontuacao, config.limiar_suspeito)

    return Veredito(pontuacao=pontuacao, nivel=nivel, motivo_forcado=motivo)