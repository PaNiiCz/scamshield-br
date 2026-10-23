"""Validação de FORMATO de chave PIX (sem rede, sem chave de API).

O DICT do Banco Central é restrito a participantes do Pix (Resolução BCB nº 118):
não existe API aberta para terceiros. Por isso aqui só se confere o formato e
existe uma interface (ConsultaChavePix) para, um dia, plugar uma fonte real.

Privacidade: a chave NUNCA é logada, guardada nem repetida nas mensagens.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class TipoChavePix(str, Enum):
    CPF = "cpf"
    CNPJ = "cnpj"
    EMAIL = "email"
    TELEFONE = "telefone"
    ALEATORIA = "aleatoria"


@dataclass(frozen=True)
class ResultadoChavePix:
    tipo: TipoChavePix | None
    valida: bool
    motivo: str


class ConsultaChavePix(Protocol):
    """Interface substituível: devolve o nome mascarado do titular, ou None."""

    def consultar(self, chave: str) -> str | None: ...


class ConsultaIndisponivel:
    """Padrão: sempre None (o DICT é restrito a participantes do Pix)."""

    def consultar(self, chave: str) -> str | None:
        return None


TAMANHO_MAXIMO_ENTRADA = 200
TAMANHO_MAXIMO_EMAIL = 77

_PESOS_CNPJ_1 = (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
_PESOS_CNPJ_2 = (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)

_RE_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
_RE_TELEFONE = re.compile(r"\+55[1-9]\d9\d{8}")
_RE_TELEFONE_SEM_55 = re.compile(r"[1-9]\d9\d{8}")
_RE_SEPARADORES = re.compile(r"[.\-/]")


def _res(tipo: TipoChavePix | None, valida: bool, motivo: str) -> ResultadoChavePix:
    return ResultadoChavePix(tipo=tipo, valida=valida, motivo=motivo)


def _cpf_valido(digitos: str) -> bool:
    if len(digitos) != 11 or not digitos.isdigit() or len(set(digitos)) == 1:
        return False
    nums = [int(c) for c in digitos]
    for posicao in (9, 10):
        soma = sum(n * (posicao + 1 - i) for i, n in enumerate(nums[:posicao]))
        resto = (soma * 10) % 11
        if (0 if resto == 10 else resto) != nums[posicao]:
            return False
    return True


def _digito_cnpj(base: str, pesos: tuple[int, ...]) -> int:
    soma = sum((ord(c) - 48) * p for c, p in zip(base, pesos))
    resto = soma % 11
    return 0 if resto < 2 else 11 - resto


def _cnpj_valido(valor: str) -> bool:
    """Aceita CNPJ numérico e o alfanumérico (valor do caractere = ord(c) - 48)."""
    if len(valor) != 14 or not re.fullmatch(r"[0-9A-Z]{12}[0-9]{2}", valor):
        return False
    if len(set(valor)) == 1:
        return False
    d1 = _digito_cnpj(valor[:12], _PESOS_CNPJ_1)
    d2 = _digito_cnpj(valor[:12] + str(d1), _PESOS_CNPJ_2)
    return valor[12:] == f"{d1}{d2}"


def _validar_uuid(chave: str) -> ResultadoChavePix:
    partes = chave.split("-")
    if partes[2][0] != "4":
        return _res(TipoChavePix.ALEATORIA, False, "A chave aleatória deve ser um UUID versão 4.")
    if partes[3][0].lower() not in "89ab":
        return _res(TipoChavePix.ALEATORIA, False, "A chave aleatória tem uma variante de UUID inválida.")
    return _res(TipoChavePix.ALEATORIA, True, "Formato de chave aleatória válido.")


def _validar_email(chave: str) -> ResultadoChavePix:
    if len(chave) > TAMANHO_MAXIMO_EMAIL:
        return _res(TipoChavePix.EMAIL, False, f"E-mail com mais de {TAMANHO_MAXIMO_EMAIL} caracteres não é aceito como chave Pix.")
    if not _RE_EMAIL.fullmatch(chave):
        return _res(TipoChavePix.EMAIL, False, "O formato do e-mail é inválido.")
    return _res(TipoChavePix.EMAIL, True, "Formato de e-mail válido.")


def _validar_telefone(chave: str) -> ResultadoChavePix:
    if _RE_TELEFONE.fullmatch(chave):
        return _res(TipoChavePix.TELEFONE, True, "Formato de telefone válido.")
    return _res(TipoChavePix.TELEFONE, False, "Telefone deve ser +55, DDD de 2 dígitos, 9 e mais 8 dígitos.")


def validar_chave_pix(chave: object) -> ResultadoChavePix:
    """Confere só o formato. 'Válida' NÃO significa que a chave exista nem que seja confiável."""
    if not isinstance(chave, str) or not chave.strip():
        return _res(None, False, "Informe uma chave Pix.")
    s = chave.strip()
    if len(s) > TAMANHO_MAXIMO_ENTRADA:
        return _res(None, False, "A entrada é longa demais para ser uma chave Pix.")

    if s.startswith("+"):
        return _validar_telefone(s)
    if "@" in s:
        return _validar_email(s)
    if _RE_UUID.fullmatch(s):
        return _validar_uuid(s)

    limpo = _RE_SEPARADORES.sub("", s).upper()
    if limpo.isdigit() and len(limpo) == 11:
        if _cpf_valido(limpo):
            return _res(TipoChavePix.CPF, True, "CPF com dígitos verificadores corretos.")
        if _RE_TELEFONE_SEM_55.fullmatch(limpo):
            return _res(TipoChavePix.TELEFONE, False, "Parece um telefone, mas falta o +55 (ex.: +5511912345678).")
        return _res(TipoChavePix.CPF, False, "CPF inválido: os dígitos verificadores não conferem.")
    if len(limpo) == 14 and re.fullmatch(r"[0-9A-Z]+", limpo):
        if _cnpj_valido(limpo):
            return _res(TipoChavePix.CNPJ, True, "CNPJ com dígitos verificadores corretos.")
        return _res(TipoChavePix.CNPJ, False, "CNPJ inválido: os dígitos verificadores não conferem.")
    return _res(None, False, "Formato não reconhecido como chave Pix.")
