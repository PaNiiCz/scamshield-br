"""Testes da integração do VirusTotal no orquestrador (Etapa 9)."""

import httpx

from backend.core.config import get_settings
from backend.core.models import MensagemEntrada
from backend.services.analysis_service import analisar_mensagem
from backend.threat_intel import virustotal_client as vt

TEXTO = "Pague agora: http://golpe-novo.xyz"


def _ligar(monkeypatch, handler):
    monkeypatch.setenv("OSINT_ATIVADO", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "chave-de-teste-nao-e-real")
    get_settings.cache_clear()
    monkeypatch.setattr(vt, "criar_cliente", lambda *a, **k: httpx.Client(transport=httpx.MockTransport(handler)))


def _resp(malicioso):
    return lambda request: httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicioso, "suspicious": 0, "harmless": 60, "undetected": 20}}}})


def _codigos(texto=TEXTO):
    return [s.codigo for s in analisar_mensagem(MensagemEntrada(texto=texto, canal="sms")).sinais]


def test_sem_chave_o_resultado_nao_muda():
    assert "virustotal_malicioso" not in _codigos()


def test_com_chave_e_dominio_marcado_o_sinal_aparece_uma_vez(monkeypatch):
    _ligar(monkeypatch, _resp(12))
    codigos = _codigos()
    assert codigos.count("virustotal_malicioso") == 1


def test_sinal_forte_do_virustotal_eleva_o_nivel(monkeypatch):
    sem = analisar_mensagem(MensagemEntrada(texto=TEXTO, canal="sms"))
    _ligar(monkeypatch, _resp(12))
    com = analisar_mensagem(MensagemEntrada(texto=TEXTO, canal="sms"))
    assert com.pontuacao >= sem.pontuacao + 45 or com.pontuacao == 100
    assert com.nivel.value in ("laranja", "vermelho")


def test_dominio_limpo_no_virustotal_nao_adiciona_sinal(monkeypatch):
    _ligar(monkeypatch, _resp(1))
    assert "virustotal_malicioso" not in _codigos()


def test_virustotal_fora_do_ar_da_o_mesmo_resultado_de_sem_chave(monkeypatch):
    base = _codigos()
    _ligar(monkeypatch, lambda request: httpx.Response(500))
    assert _codigos() == base


def test_chave_errada_nao_derruba_a_analise(monkeypatch):
    _ligar(monkeypatch, lambda request: httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}}))
    assert "virustotal_malicioso" not in _codigos()