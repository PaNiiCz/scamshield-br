"""Mascaramento de dados pessoais (PII) do ScamShield BR.

Regra do projeto: nenhum dado sensível é salvo, logado ou cacheado em
texto puro. Toda vez que algo for persistido, passe o texto por aqui antes.

Limitação conhecida: o mascaramento usa padrões de formato. Ele cobre
CPF, CNPJ, e-mail, telefone, cartão e chave PIX aleatória, mas NÃO
detecta nomes de pessoas nem endereços.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Padrões
# ---------------------------------------------------------------------------

_EMAIL = r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"

# 16 dígitos, com ou sem espaço/hífen entre os grupos de 4
_CARTAO = r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"

# 12.345.678/0001-95  (pontuação opcional)
_CNPJ = r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"

# CPF com pontuação: 123.456.789-09 | 123456789-09
_CPF_FORMATADO = r"\b\d{3}\.?\d{3}\.?\d{3}[.-]\d{2}\b"

# Exatamente 11 dígitos colados (pode ser CPF ou telefone com DDD)
_ONZE_DIGITOS = r"(?<!\d)\d{11}(?!\d)"

# Chave PIX aleatória = UUID
_UUID = (
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# Telefone brasileiro, em duas formas:
#  A) com DDD (e opcionalmente +55): (21) 99999-8888 | 21999998888 | +55 21 3333-4444
#  B) celular de 9 dígitos sem DDD:  99999-8888
_TELEFONE = (
    r"(?<!\d)(?:\+?55\s?)?\(?\d{2}\)?\s?(?:9\s?\d{4}|\d{4})[\s-]?\d{4}(?!\d)"
    r"|(?<!\d)9\d{4}-\d{4}(?!\d)"
)


def _cpf_valido(texto: str) -> bool:
    """Confere os dois dígitos verificadores do CPF.

    Usado só para decidir se 11 dígitos colados são mesmo um CPF
    (e não um telefone com DDD).
    """
    digitos = re.sub(r"\D", "", texto)
    if len(digitos) != 11 or digitos == digitos[0] * 11:
        return False
    for tamanho in (9, 10):
        pesos = range(tamanho + 1, 1, -1)  # 10..2 na 1ª conta, 11..2 na 2ª
        soma = sum(int(d) * p for d, p in zip(digitos[:tamanho], pesos))
        digito_esperado = (soma * 10) % 11 % 10
        if digito_esperado != int(digitos[tamanho]):
            return False
    return True


# Cada etapa: (nome para a contagem, texto que substitui, regex, validador opcional)
# A ORDEM importa: padrões mais específicos vêm antes dos mais genéricos.
_ETAPAS: list[tuple[str, str, str, Callable[[str], bool] | None]] = [
    ("email", "[EMAIL]", _EMAIL, None),
    ("cartao", "[CARTAO]", _CARTAO, None),
    ("cnpj", "[CNPJ]", _CNPJ, None),
    ("cpf", "[CPF]", _CPF_FORMATADO, None),
    ("cpf", "[CPF]", _ONZE_DIGITOS, _cpf_valido),  # 11 colados só se for CPF válido
    ("chave_pix", "[CHAVE_PIX]", _UUID, None),
    ("telefone", "[TELEFONE]", _TELEFONE, None),
    # Rede de segurança: 11 dígitos que não são CPF válido nem telefone.
    ("documento", "[DOCUMENTO]", _ONZE_DIGITOS, None),
]

_ETAPAS_COMPILADAS = [
    (nome, substituto, re.compile(regex), validador)
    for nome, substituto, regex, validador in _ETAPAS
]


@dataclass(frozen=True)
class ResultadoMascaramento:
    """Texto já mascarado + quantos dados de cada tipo foram encontrados."""

    texto: str
    contagem: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.contagem.values())


def mascarar_com_contagem(texto: str) -> ResultadoMascaramento:
    """Mascara o texto e informa quantos itens de cada tipo foram trocados."""
    contagem: dict[str, int] = {}

    for nome, substituto, padrao, validador in _ETAPAS_COMPILADAS:

        def trocar(
            achado: re.Match[str],
            nome: str = nome,
            substituto: str = substituto,
            validador: Callable[[str], bool] | None = validador,
        ) -> str:
            # Se há validador e ele recusa, devolve o trecho original sem mexer
            if validador is not None and not validador(achado.group()):
                return achado.group()
            contagem[nome] = contagem.get(nome, 0) + 1
            return substituto

        texto = padrao.sub(trocar, texto)

    return ResultadoMascaramento(texto=texto, contagem=contagem)


def mascarar_pii(texto: str) -> str:
    """Devolve o texto com todos os dados pessoais reconhecidos mascarados."""
    return mascarar_com_contagem(texto).texto