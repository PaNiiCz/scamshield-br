"""Testes da integração do OSINT no orquestrador e na API (Etapa 8)."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.core.config import get_settings
from backend.core.models import MensagemEntrada
from backend.main import app
from backend.osint import osint_service
from backend.services.analysis_service import analisar_mensagem

GOLPE = "CLARO: sua fatura vence hoje! Pague via PIX: http://claro-fatura.xyz"


def _rede(falhar_tudo: bool = False):
    data = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    pedidos = []

    def handler(request):
        pedidos.append(request)
        if falhar_tudo:
            return httpx.Response(503)
        if request.url.host == "archive.org":
            return httpx.Response(200, json={"archived_snapshots": {}})
        return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": data}]})

    return handler, pedidos


@pytest.fixture
def ligar(monkeypatch):
    def _ligar(handler):
        monkeypatch.setenv("OSINT_ATIVADO", "true")
        get_settings.cache_clear()
        monkeypatch.setattr(
            osint_service,
            "criar_cliente",
            lambda *a, **k: httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True),
        )

    return _ligar


def _codigos(r):
    return [s.codigo for s in r.sinais]


def test_osint_desligado_nao_adiciona_sinais_nem_consulta():
    r = analisar_mensagem(MensagemEntrada(texto=GOLPE))
    assert "dominio_recente" not in _codigos(r)
    assert "site_sem_historico" not in _codigos(r)


def test_osint_ligado_adiciona_sinais_ao_resultado(ligar):
    handler, _ = _rede()
    sem = analisar_mensagem(MensagemEntrada(texto=GOLPE))
    ligar(handler)
    com = analisar_mensagem(MensagemEntrada(texto=GOLPE))
    assert "dominio_recente" in _codigos(com)
    assert "site_sem_historico" in _codigos(com)
    assert com.pontuacao >= sem.pontuacao
    assert len(com.sinais) == len(sem.sinais) + 2


def test_sinais_do_osint_aparecem_uma_so_vez(ligar):
    handler, _ = _rede()
    ligar(handler)
    codigos = _codigos(analisar_mensagem(MensagemEntrada(texto=GOLPE)))
    assert codigos.count("dominio_recente") == 1
    assert codigos.count("site_sem_historico") == 1
    assert codigos.count("url_com_ip") <= 1


def test_servico_fora_do_ar_da_o_mesmo_resultado_de_osint_desligado(ligar):
    base = analisar_mensagem(MensagemEntrada(texto=GOLPE))
    handler, _ = _rede(falhar_tudo=True)
    ligar(handler)
    r = analisar_mensagem(MensagemEntrada(texto=GOLPE))
    assert _codigos(r) == _codigos(base)
    assert r.pontuacao == base.pontuacao


def test_mensagem_sem_link_nao_consulta_nada(ligar):
    handler, pedidos = _rede()
    ligar(handler)
    r = analisar_mensagem(MensagemEntrada(texto="Oi, tudo bem? Vamos almoçar amanhã?"))
    assert r.nivel.value == "verde"
    assert pedidos == []


def test_site_oficial_continua_verde_e_nao_e_consultado(ligar):
    handler, pedidos = _rede()
    ligar(handler)
    r = analisar_mensagem(
        MensagemEntrada(texto="Sua fatura de outubro já está disponível em https://www.claro.com.br")
    )
    assert r.nivel.value == "verde"
    assert pedidos == []


def test_resultado_pela_api_inclui_sinais_do_osint(ligar):
    handler, _ = _rede()
    ligar(handler)
    resposta = TestClient(app).post("/analisar", json={"texto": GOLPE, "canal": "sms"})
    assert resposta.status_code == 200
    codigos = [s["codigo"] for s in resposta.json()["sinais"]]
    assert "dominio_recente" in codigos