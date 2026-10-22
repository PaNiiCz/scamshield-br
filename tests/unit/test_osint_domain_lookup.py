"""Testes da consulta de idade do domínio via RDAP (Etapa 8). Sem rede."""

from datetime import datetime, timezone

import httpx
import pytest

from backend.core.errors import ServicoExternoError
from backend.osint.domain_lookup import (
    analisar_idade_dominio,
    consultar_data_registro,
)

AGORA = datetime(2026, 10, 20, tzinfo=timezone.utc)


def _cliente(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def _resposta_rdap(data: str) -> dict:
    return {
        "ldhName": "x.com.br",
        "events": [
            {"eventAction": "last changed", "eventDate": "2025-01-01T00:00:00Z"},
            {"eventAction": "registration", "eventDate": data},
        ],
    }


def test_dominio_br_usa_o_rdap_do_registro_br():
    urls = []

    def handler(request):
        urls.append(str(request.url))
        return httpx.Response(200, json=_resposta_rdap("1998-12-14T15:34:16Z"))

    data = consultar_data_registro("claro.com.br", _cliente(handler))
    assert urls == ["https://rdap.registro.br/domain/claro.com.br"]
    assert data == datetime(1998, 12, 14, 15, 34, 16, tzinfo=timezone.utc)


def test_dominio_nao_br_usa_o_bootstrap_do_rdap_org():
    urls = []

    def handler(request):
        urls.append(str(request.url))
        return httpx.Response(200, json=_resposta_rdap("1995-08-14T04:00:00Z"))

    data = consultar_data_registro("example.com", _cliente(handler))
    assert urls == ["https://rdap.org/domain/example.com"]
    assert data.year == 1995


def test_segue_redirecionamento_do_rdap_org():
    def handler(request):
        if request.url.host == "rdap.org":
            return httpx.Response(
                302, headers={"location": "https://rdap.verisign.com/com/v1/domain/example.com"}
            )
        return httpx.Response(200, json=_resposta_rdap("1995-08-14T04:00:00Z"))

    assert consultar_data_registro("example.com", _cliente(handler)).year == 1995


def test_404_significa_nao_sei_e_devolve_none():
    cliente = _cliente(lambda request: httpx.Response(404))
    assert consultar_data_registro("inexistente-123.com.br", cliente) is None


def test_json_sem_evento_de_registro_devolve_none():
    cliente = _cliente(lambda r: httpx.Response(200, json={"events": []}))
    assert consultar_data_registro("a.com.br", cliente) is None


def test_data_invalida_devolve_none():
    cliente = _cliente(lambda r: httpx.Response(200, json=_resposta_rdap("isso-nao-e-data")))
    assert consultar_data_registro("a.com.br", cliente) is None


def test_erro_do_servidor_vira_servico_externo_error():
    cliente = _cliente(lambda r: httpx.Response(500))
    with pytest.raises(ServicoExternoError):
        consultar_data_registro("a.com.br", cliente)


def test_resposta_que_nao_e_json_vira_servico_externo_error():
    cliente = _cliente(lambda r: httpx.Response(200, text="<html>oi</html>"))
    with pytest.raises(ServicoExternoError):
        consultar_data_registro("a.com.br", cliente)


def test_timeout_vira_servico_externo_error():
    def handler(request):
        raise httpx.ConnectTimeout("demorou", request=request)

    with pytest.raises(ServicoExternoError):
        consultar_data_registro("a.com.br", _cliente(handler))


@pytest.mark.parametrize("nome", ["../etc/passwd", "a b.com", "a.com/x", "", "a" * 300 + ".com"])
def test_nome_estranho_e_recusado_sem_consultar(nome):
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json={})

    with pytest.raises(ServicoExternoError):
        consultar_data_registro(nome, _cliente(handler))
    assert chamadas == []


# --- Sinais ---------------------------------------------------------------


def test_dominio_de_10_dias_gera_sinal_de_25_pontos():
    sinal = analisar_idade_dominio("golpe.xyz", datetime(2026, 10, 10, tzinfo=timezone.utc), AGORA)
    assert sinal.codigo == "dominio_recente"
    assert sinal.pontos == 25
    assert sinal.forte is False
    assert sinal.origem == "osint"
    assert "golpe.xyz" in sinal.descricao
    assert "10 dias" in sinal.descricao


def test_dominio_de_60_dias_gera_sinal_de_15_pontos():
    sinal = analisar_idade_dominio("golpe.xyz", datetime(2026, 8, 21, tzinfo=timezone.utc), AGORA)
    assert sinal.pontos == 15


def test_limites_exatos_29_30_89_90_dias():
    def dias(n):
        from datetime import timedelta
        return analisar_idade_dominio("a.com", AGORA - timedelta(days=n), AGORA)

    assert dias(29).pontos == 25
    assert dias(30).pontos == 15
    assert dias(89).pontos == 15
    assert dias(90) is None


def test_dominio_antigo_nao_gera_sinal():
    assert analisar_idade_dominio("claro.com.br", datetime(1998, 12, 14, tzinfo=timezone.utc), AGORA) is None


def test_sem_data_nao_gera_sinal():
    assert analisar_idade_dominio("a.com", None, AGORA) is None


def test_data_no_futuro_nao_gera_sinal():
    assert analisar_idade_dominio("a.com", datetime(2027, 1, 1, tzinfo=timezone.utc), AGORA) is None


def test_dominio_de_1_dia_usa_singular():
    sinal = analisar_idade_dominio("a.com", datetime(2026, 10, 19, tzinfo=timezone.utc), AGORA)
    assert "1 dia" in sinal.descricao
    assert "1 dias" not in sinal.descricao