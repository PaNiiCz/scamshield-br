"""Testes da análise de arquivo por hash (Etapa 9). O arquivo NUNCA é aberto,
executado nem enviado: só o SHA-256 dele é calculado e consultado."""

import hashlib

import httpx
import pytest

from backend.core.config import get_settings
from backend.core.errors import EntradaInvalidaError
from backend.file_check import file_hash_analyzer as fha
from backend.file_check.file_hash_analyzer import (
    ArquivoGrandeDemaisError,
    CalculadoraHash,
    analisar_hash,
    analisar_hash_do_arquivo,
    sinal_de_arquivo,
)
from backend.threat_intel import virustotal_client as vt
from backend.threat_intel.virustotal_client import ReputacaoVT

CHAVE = "chave-de-teste-nao-e-real"
SHA_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
SHA_EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _vt_stats(malicioso=0, suspeito=0, inofensivo=0, nao_detectado=60):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicioso, "suspicious": suspeito, "harmless": inofensivo,
        "undetected": nao_detectado, "type-unsupported": 7}}}}


def _cliente(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def _json(dados, status=200):
    return lambda request: httpx.Response(status, json=dados)


# --- CalculadoraHash --------------------------------------------------------------


def test_hash_de_abc_confere_com_o_valor_conhecido():
    calc = CalculadoraHash()
    calc.adicionar(b"abc")
    assert calc.resultado() == (SHA_ABC, 3)


def test_hash_em_pedacos_e_igual_ao_hash_de_uma_vez():
    dados = bytes(range(256)) * 100
    calc = CalculadoraHash()
    for i in range(0, len(dados), 1000):
        calc.adicionar(dados[i:i + 1000])
    assert calc.resultado() == (hashlib.sha256(dados).hexdigest(), len(dados))


def test_arquivo_vazio_tem_tamanho_zero():
    assert CalculadoraHash().resultado()[1] == 0


def test_arquivo_exatamente_no_limite_e_aceito():
    calc = CalculadoraHash(limite=5)
    calc.adicionar(b"12345")
    assert calc.resultado()[1] == 5


def test_arquivo_acima_do_limite_e_recusado():
    calc = CalculadoraHash(limite=5)
    calc.adicionar(b"123")
    with pytest.raises(ArquivoGrandeDemaisError):
        calc.adicionar(b"456")


def test_erro_de_tamanho_e_um_erro_de_entrada_invalida():
    assert issubclass(ArquivoGrandeDemaisError, EntradaInvalidaError)


def test_limite_padrao_e_25_mb():
    assert fha.LIMITE_BYTES == 25 * 1024 * 1024


# --- sinal_de_arquivo --------------------------------------------------------------


@pytest.mark.parametrize("marcados", [0, 1, 2])
def test_poucos_motores_nao_geram_sinal_de_arquivo(marcados):
    assert sinal_de_arquivo(ReputacaoVT(malicioso=marcados, nao_detectado=60)) is None


@pytest.mark.parametrize("marcados, pontos, forte", [(3, 30, False), (9, 30, False), (10, 60, True), (66, 60, True)])
def test_faixas_do_sinal_de_arquivo(marcados, pontos, forte):
    sinal = sinal_de_arquivo(ReputacaoVT(malicioso=marcados, nao_detectado=60))
    assert (sinal.codigo, sinal.pontos, sinal.forte, sinal.origem) == ("arquivo_malicioso", pontos, forte, "virustotal")


# --- analisar_hash ------------------------------------------------------------------


def test_arquivo_conhecido_e_perigoso_fica_vermelho():
    r = analisar_hash(SHA_EICAR, 68, CHAVE, _cliente(_json(_vt_stats(malicioso=66, nao_detectado=2))))
    assert r.nivel.value == "vermelho"
    assert r.virustotal_consultado is True and r.conhecido_no_virustotal is True
    assert (r.motores_marcaram, r.motores_total) == (66, 68)
    assert [s.codigo for s in r.sinais] == ["arquivo_malicioso"]
    assert "Não abra" in r.resumo


def test_poucos_motores_marcando_fica_laranja():
    r = analisar_hash(SHA_ABC, 3, CHAVE, _cliente(_json(_vt_stats(malicioso=4))))
    assert r.nivel.value == "laranja"


def test_arquivo_conhecido_e_limpo_fica_verde_sem_afirmar_seguranca():
    r = analisar_hash(SHA_ABC, 3, CHAVE, _cliente(_json(_vt_stats(malicioso=0, inofensivo=30))))
    assert r.nivel.value == "verde" and r.sinais == []
    assert "não garante" in r.resumo


def test_arquivo_desconhecido_nao_e_dito_seguro():
    r = analisar_hash(SHA_ABC, 3, CHAVE, _cliente(lambda req: httpx.Response(404, json={"error": {}})))
    assert r.conhecido_no_virustotal is False and r.virustotal_consultado is True
    assert r.sinais == []
    assert "NÃO significa" in r.resumo
    assert r.motores_marcaram is None and r.motores_total is None


def test_sem_chave_devolve_so_o_hash():
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json=_vt_stats())

    r = analisar_hash(SHA_ABC, 3, "", _cliente(handler))
    assert chamadas == []
    assert r.virustotal_consultado is False and r.conhecido_no_virustotal is None
    assert r.sha256 == SHA_ABC and r.tamanho_bytes == 3
    assert "SHA-256" in r.resumo


def test_falha_do_virustotal_nao_derruba_e_avisa():
    r = analisar_hash(SHA_ABC, 3, CHAVE, _cliente(lambda req: httpx.Response(500)))
    assert r.virustotal_consultado is False
    assert r.sinais == [] and r.nivel.value == "verde"
    assert "Não foi possível consultar" in r.resumo


def test_limite_local_de_consultas_nao_derruba(monkeypatch):
    monkeypatch.setattr(vt, "_limitador", vt.LimitadorVT(por_minuto=0))
    r = analisar_hash(SHA_ABC, 3, CHAVE, _cliente(_json(_vt_stats())))
    assert r.virustotal_consultado is False


def test_so_o_hash_vai_ao_virustotal_nunca_o_conteudo():
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(404, json={"error": {}})

    analisar_hash(SHA_ABC, 3, CHAVE, _cliente(handler))
    assert len(pedidos) == 1
    assert pedidos[0].method == "GET"
    assert pedidos[0].url.path == f"/api/v3/files/{SHA_ABC}"
    assert pedidos[0].content == b""


# --- analisar_hash_do_arquivo (lê as configurações) -------------------------------------


def test_com_osint_desligado_nem_cria_cliente(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", CHAVE)
    get_settings.cache_clear()
    criou = []
    monkeypatch.setattr(vt, "criar_cliente", lambda *a, **k: criou.append(1))
    r = analisar_hash_do_arquivo(SHA_ABC, 3)
    assert criou == [] and r.virustotal_consultado is False


def test_com_chave_e_osint_ligado_consulta(monkeypatch):
    monkeypatch.setenv("OSINT_ATIVADO", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", CHAVE)
    get_settings.cache_clear()
    monkeypatch.setattr(vt, "criar_cliente", lambda *a, **k: _cliente(_json(_vt_stats(malicioso=66, nao_detectado=2))))
    r = analisar_hash_do_arquivo(SHA_EICAR, 68)
    assert r.nivel.value == "vermelho"