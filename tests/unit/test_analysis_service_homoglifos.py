"""Testes da integração dos homóglifos no orquestrador e na API (Etapa 8.5)."""

import httpx
from fastapi.testclient import TestClient

from backend.core.config import get_settings
from backend.core.models import MensagemEntrada
from backend.main import app
from backend.osint import osint_service
from backend.services.analysis_service import analisar_mensagem

A_CIR = "\u0430"
P_CIR = "\u0440"

DOMINIO = "dominio_com_letras_falsas"
TEXTO = "letras_trocadas_no_texto"


def _analisar(texto, canal="sms"):
    return analisar_mensagem(MensagemEntrada(texto=texto, canal=canal))


def _codigos(resultado):
    return [s.codigo for s in resultado.sinais]


def test_link_oficial_com_letra_falsa_deixa_de_passar_batido():
    # Antes: 0 sinais e nível verde. Agora: sinal forte, no mínimo laranja.
    r = _analisar(f"Sua fatura está em https://www.cl{A_CIR}ro.com.br/fatura")
    assert DOMINIO in _codigos(r)
    assert r.nivel.value in ("laranja", "vermelho")
    assert r.pontuacao >= 30


def test_link_oficial_de_verdade_continua_verde():
    r = _analisar("Sua fatura está em https://www.claro.com.br/fatura")
    assert r.nivel.value == "verde"
    assert [s for s in r.sinais if s.origem == "homoglyph_analyzer"] == []
    assert [s for s in r.sinais if s.origem == "url_analyzer"] == []


def test_pix_escrito_com_letra_falsa_agora_aciona_a_regra_de_pix():
    r = _analisar(f"Pague via {P_CIR}ix imediatamente")
    codigos = _codigos(r)
    assert "pedido_pix" in codigos
    assert TEXTO in codigos


def test_golpe_da_claro_com_letra_falsa_nao_pontua_menos_que_o_original():
    original = _analisar(
        "CLARO: sua fatura está em atraso e sua linha será bloqueada hoje! "
        "Pague via PIX imediatamente: http://claro-fatura.xyz"
    )
    disfarcado = _analisar(
        "CLARO: sua fatura está em atraso e sua linha será bloqueada hoje! "
        f"Pague via {P_CIR}IX imediatamente: http://cl{A_CIR}ro-fatura.xyz"
    )
    assert "dominio_imitando_marca" in _codigos(disfarcado)  # via letras desfeitas
    assert DOMINIO in _codigos(disfarcado)
    assert disfarcado.pontuacao >= original.pontuacao
    assert disfarcado.nivel.value == "vermelho"


def test_mensagens_normais_nao_mudam():
    r = _analisar("Oi, tudo bem? Vamos almoçar amanhã? Atenção ao horário, você não pode faltar.")
    assert r.nivel.value == "verde"
    assert r.pontuacao == 0


def test_texto_em_russo_legitimo_nao_vira_golpe():
    r = _analisar("\u041f\u0440\u0438\u0432\u0435\u0442, \u043a\u0430\u043a \u0434\u0435\u043b\u0430?")
    assert r.nivel.value == "verde"
    assert DOMINIO not in _codigos(r)
    assert TEXTO not in _codigos(r)


def test_nenhum_sinal_aparece_duplicado():
    r = _analisar(f"Pague via {P_CIR}ix em http://cl{A_CIR}ro-fatura.xyz e https://www.cl{A_CIR}ro.com.br")
    codigos = _codigos(r)
    assert len(codigos) == len(set(codigos))


def test_pela_api_com_acentos_e_letras_falsas():
    resposta = TestClient(app).post(
        "/analisar",
        json={"texto": f"Atenção! Acesse https://www.cl{A_CIR}ro.com.br/fatura", "canal": "whatsapp"},
    )
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert DOMINIO in [s["codigo"] for s in corpo["sinais"]]
    assert corpo["nivel"] in ("laranja", "vermelho")


def test_osint_nunca_consulta_o_endereco_com_letras_desfeitas(monkeypatch):
    # O endereço verdadeiro é o cirílico. Consultar o "irmão latino"
    # (claro-fatura.xyz) traria dados de OUTRO domínio e enganaria a análise.
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(404)

    monkeypatch.setenv("OSINT_ATIVADO", "true")
    get_settings.cache_clear()
    monkeypatch.setattr(
        osint_service,
        "criar_cliente",
        lambda *a, **k: httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True),
    )
    _analisar(f"Pague em http://cl{A_CIR}ro-fatura.xyz")
    consultados = [str(p.url) for p in pedidos]
    assert not any("claro-fatura.xyz" in url for url in consultados)