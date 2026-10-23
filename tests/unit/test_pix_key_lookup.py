import time

import pytest

from backend.finance_check import pix_key_lookup as pk
from backend.finance_check.pix_key_lookup import (
    ConsultaIndisponivel,
    TipoChavePix,
    validar_chave_pix,
)

UUID_OK = "123e4567-e89b-42d3-a456-426614174000"


@pytest.mark.parametrize("chave", ["529.982.247-25", "52998224725", " 529.982.247-25 "])
def test_cpf_valido(chave):
    r = validar_chave_pix(chave)
    assert r.valida and r.tipo == TipoChavePix.CPF


@pytest.mark.parametrize("chave", ["12345678900", "111.111.111-11", "00000000000"])
def test_cpf_invalido(chave):
    r = validar_chave_pix(chave)
    assert not r.valida and r.tipo == TipoChavePix.CPF


@pytest.mark.parametrize("chave", ["11.222.333/0001-81", "11222333000181", "12.ABC.345/01DE-35", "12ABC34501DE35", "12abc34501de35"])
def test_cnpj_valido(chave):
    r = validar_chave_pix(chave)
    assert r.valida and r.tipo == TipoChavePix.CNPJ


@pytest.mark.parametrize("chave", ["11222333000182", "12ABC34501DE36", "00000000000000", "12ABC34501DEAB"])
def test_cnpj_invalido(chave):
    r = validar_chave_pix(chave)
    assert not r.valida and r.tipo == TipoChavePix.CNPJ


def test_digitos_cnpj_conferidos_a_mao():
    assert pk._digito_cnpj("12ABC34501DE", pk._PESOS_CNPJ_1) == 3
    assert pk._digito_cnpj("12ABC34501DE3", pk._PESOS_CNPJ_2) == 5
    assert pk._digito_cnpj("112223330001", pk._PESOS_CNPJ_1) == 8
    assert pk._digito_cnpj("1122233300018", pk._PESOS_CNPJ_2) == 1


def test_email_valido_e_invalido():
    assert validar_chave_pix("maria.silva@exemplo.com.br").tipo == TipoChavePix.EMAIL
    assert validar_chave_pix("maria.silva@exemplo.com.br").valida
    for ruim in ["maria@", "@exemplo.com", "maria@exemplo", "ma ria@exemplo.com"]:
        r = validar_chave_pix(ruim)
        assert r.tipo == TipoChavePix.EMAIL and not r.valida


def test_email_limite_77():
    ok = "a" * 64 + "@b.co"  # 69
    assert validar_chave_pix(ok).valida
    longo = "a" * 73 + "@b.co"  # 78
    r = validar_chave_pix(longo)
    assert not r.valida and "77" in r.motivo


def test_telefone_valido_e_invalido():
    r = validar_chave_pix("+5511987654321")
    assert r.valida and r.tipo == TipoChavePix.TELEFONE
    for ruim in ["+551187654321", "+5511887654321", "+5501987654321", "+55119876543210"]:
        r = validar_chave_pix(ruim)
        assert r.tipo == TipoChavePix.TELEFONE and not r.valida


def test_telefone_sem_55_explica():
    r = validar_chave_pix("11987654321")
    assert not r.valida and r.tipo == TipoChavePix.TELEFONE and "+55" in r.motivo


def test_onze_digitos_que_passam_como_cpf_sao_cpf():
    r = validar_chave_pix("52998224725")  # parece telefone (DDD 52, 3o digito 9), mas e CPF valido
    assert r.valida and r.tipo == TipoChavePix.CPF


def test_uuid_valido_case_insensitive():
    assert validar_chave_pix(UUID_OK).valida
    r = validar_chave_pix(UUID_OK.upper())
    assert r.valida and r.tipo == TipoChavePix.ALEATORIA


def test_uuid_versao_e_variante_erradas():
    assert not validar_chave_pix("123e4567-e89b-12d3-a456-426614174000").valida
    r = validar_chave_pix("123e4567-e89b-42d3-c456-426614174000")
    assert not r.valida and r.tipo == TipoChavePix.ALEATORIA


@pytest.mark.parametrize("entrada", ["", "   ", None, 123, [], b"abc"])
def test_entrada_vazia_ou_nao_texto(entrada):
    r = validar_chave_pix(entrada)
    assert not r.valida and r.tipo is None


def test_entrada_gigante_rapida():
    inicio = time.perf_counter()
    for texto in ["1" * 100000, "a" * 100000 + "@", "+" + "5" * 100000, "-" * 100000]:
        r = validar_chave_pix(texto)
        assert not r.valida
    assert time.perf_counter() - inicio < 0.5


def test_formato_desconhecido():
    r = validar_chave_pix("abc")
    assert not r.valida and r.tipo is None


def test_motivo_nunca_repete_a_chave():
    for chave in ["52998224724", "maria@exemplo", "+5511887654321", "11222333000182", UUID_OK[:-1] + "x"]:
        r = validar_chave_pix(chave)
        assert chave not in r.motivo


def test_interface_padrao_devolve_none():
    assert ConsultaIndisponivel().consultar("52998224725") is None