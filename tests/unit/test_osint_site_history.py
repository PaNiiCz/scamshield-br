"""Testes do histórico de site via Archive.org (Etapa 8). Sem rede."""

import httpx
import pytest

from backend.core.errors import ServicoExternoError
from backend.osint.site_history import analisar_historico, tem_historico


def _cliente(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


COM_HISTORICO = {
    "url": "claro.com.br",
    "archived_snapshots": {
        "closest": {"status": "200", "available": True, "timestamp": "20261017102647"}
    },
}
SEM_HISTORICO = {"url": "golpe.xyz", "archived_snapshots": {}}


def test_consulta_a_api_certa_so_com_o_dominio():
    urls = []

    def handler(request):
        urls.append(request)
        return httpx.Response(200, json=COM_HISTORICO)

    tem_historico("claro.com.br", _cliente(handler))
    assert urls[0].url.host == "archive.org"
    assert urls[0].url.path == "/wayback/available"
    assert dict(urls[0].url.params) == {"url": "claro.com.br"}


def test_com_snapshot_devolve_true():
    assert tem_historico("claro.com.br", _cliente(lambda r: httpx.Response(200, json=COM_HISTORICO))) is True


def test_sem_snapshot_devolve_false():
    assert tem_historico("golpe.xyz", _cliente(lambda r: httpx.Response(200, json=SEM_HISTORICO))) is False


def test_formato_inesperado_devolve_none():
    assert tem_historico("a.com", _cliente(lambda r: httpx.Response(200, json={"foo": 1}))) is None


def test_erro_do_servidor_vira_servico_externo_error():
    with pytest.raises(ServicoExternoError):
        tem_historico("a.com", _cliente(lambda r: httpx.Response(503)))


def test_nao_json_vira_servico_externo_error():
    with pytest.raises(ServicoExternoError):
        tem_historico("a.com", _cliente(lambda r: httpx.Response(200, text="oops")))


def test_timeout_vira_servico_externo_error():
    def handler(request):
        raise httpx.ReadTimeout("demorou", request=request)

    with pytest.raises(ServicoExternoError):
        tem_historico("a.com", _cliente(handler))


@pytest.mark.parametrize("nome", ["a b.com", "a.com?x=1", "", "a.com/../x"])
def test_nome_estranho_e_recusado_sem_consultar(nome):
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json={})

    with pytest.raises(ServicoExternoError):
        tem_historico(nome, _cliente(handler))
    assert chamadas == []


def test_sinal_so_quando_nao_ha_historico():
    sinal = analisar_historico("golpe.xyz", False)
    assert sinal.codigo == "site_sem_historico"
    assert sinal.pontos == 10
    assert sinal.forte is False
    assert sinal.origem == "osint"
    assert "golpe.xyz" in sinal.descricao


def test_sem_sinal_quando_tem_historico_ou_nao_sabe():
    assert analisar_historico("claro.com.br", True) is None
    assert analisar_historico("a.com", None) is None