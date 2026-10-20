"""Modelos de dados do ScamShield BR.

Definem o formato do que entra (Mensagem) e do que sai (Resultado)
da análise, e as peças intermediárias (Sinal).
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Canal(str, Enum):
    """Por onde a mensagem suspeita chegou."""

    WHATSAPP = "whatsapp"
    SMS = "sms"
    EMAIL = "email"


class NivelRisco(str, Enum):
    """Resultado graduado. Nunca afirmamos certeza absoluta."""

    VERDE = "verde"        # 🟢 sem sinais fortes
    LARANJA = "laranja"    # 🟠 suspeito
    VERMELHO = "vermelho"  # 🔴 alto risco


class TipoGolpe(str, Enum):
    """Categorias de golpe que o sistema sabe reconhecer."""

    BOLETO = "boleto"
    PIX = "pix"
    FALSO_PARENTE = "falso_parente"
    FALSA_OPERADORA = "falsa_operadora"
    CONTA_BLOQUEADA = "conta_bloqueada"
    OUTRO = "outro"


class Sinal(BaseModel):
    """Um indício encontrado por algum analisador.

    É a base da explicabilidade: o sistema nunca devolve só um número,
    devolve a lista de sinais que o justificam.
    """

    codigo: str = Field(description="Identificador curto, ex: 'urgencia_falsa'")
    descricao: str = Field(description="Explicação em português para o usuário")
    pontos: int = Field(ge=0, le=100, description="Quanto este sinal pesa no risco")
    origem: str = Field(description="Qual módulo encontrou, ex: 'rules', 'url_analyzer'")
    forte: bool = Field(
        default=False,
        description="Sinal forte: ajuda a forçar no mínimo nível laranja",
    )


class MensagemEntrada(BaseModel):
    """O que o usuário envia para ser analisado."""

    model_config = ConfigDict(str_strip_whitespace=True)

    texto: str = Field(min_length=1, max_length=10_000)
    canal: Canal = Canal.WHATSAPP
    # Só usado quando o canal é e-mail: cabeçalhos brutos da mensagem
    cabecalhos_email: str | None = Field(default=None, max_length=20_000)


class ResultadoAnalise(BaseModel):
    """O que o sistema devolve depois de analisar."""

    pontuacao: int = Field(ge=0, le=100)
    nivel: NivelRisco
    sinais: list[Sinal] = Field(default_factory=list)
    tipo_golpe: TipoGolpe | None = None
    resumo: str = ""