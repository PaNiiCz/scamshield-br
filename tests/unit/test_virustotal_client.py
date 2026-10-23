"""Testes do cliente do VirusTotal (Etapa 9). As respostas de exemplo seguem o
formato REAL visto na verificação. Nenhum teste usa a internet nem a sua chave."""

import threading
from datetime import date

import httpx
import pytest

from backend.core.config import get_settings
from backend.core.errors import ServicoExternoError
from backend.threat_intel import virustotal_client as vt
from backend.threat_intel.virustotal_client import (
    LimitadorVT,
    ReputacaoVT,
    analisar_virustotal,
    consultar_arquivo,
    consultar_dominio,
    reputacao_do_arquivo,
    reputacao_do_dominio,
    sinal_de_dominio,
)

CHAVE = "chave-de-teste-nao-e-real"
SHA_EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

GOOGLE = {
    "data": {
        "type": "domain",
        "id": "google.com",
        "attributes": {
            "last_analysis_stats": {"malicious": 1, "suspicious": 0, "undetected": 30, "harmless": 61, "timeout": 0}
        },
    }
}
EICAR = {
    "data": {
        "type": "file",
        "id": SHA_EICAR,
        "attributes": {
            "last_analysis_stats": {
                "malicious": 66, "suspicious": 0, "undetected": 2, "harmless": 0,
                "timeout": 0, "confirmed-timeout": 0, "failure": 0, "type-unsupported": 7,
            }
        },
    }
}


def _stats(malicioso=0, suspeito=0, inofensivo=60, nao_detectado=30) -> dict:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicioso, "suspicious": suspeito,
                    "harmless": inofensivo, "undetected": nao_detectado, "timeout": 0,
                }
            }
        }
    }


def _cliente(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def _json(dados, status=200):
    return lambda request: httpx.Response(status, json=dados)


# --- consultar_dominio / consultar_arquivo ------------------------------------


def test_consulta_so_o_dominio_e_manda_a_chave_so_no_cabecalho():
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(200, json=GOOGLE)

    consultar_dominio("google.com", CHAVE, _cliente(handler))
    pedido = pedidos[0]
    assert str(pedido.url) == "https://www.virustotal.com/api/v3/domains/google.com"
    assert pedido.method == "GET"
    assert pedido.headers["x-apikey"] == CHAVE
    assert CHAVE not in str(pedido.url)


def test_le_as_contagens_do_dominio_conhecido():
    rep = consultar_dominio("google.com", CHAVE, _cliente(_json(GOOGLE)))
    assert rep == ReputacaoVT(malicioso=1, suspeito=0, inofensivo=61, nao_detectado=30)
    assert rep.marcados == 1
    assert rep.total == 92


def test_motores_sem_veredito_nao_entram_na_conta():
    rep = consultar_arquivo(SHA_EICAR, CHAVE, _cliente(_json(EICAR)))
    assert rep.malicioso == 66
    assert rep.total == 68  # os 7 "type-unsupported" ficam de fora


def test_arquivo_consulta_o_caminho_certo_e_aceita_maiusculas():
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(200, json=EICAR)

    consultar_arquivo(SHA_EICAR.upper(), CHAVE, _cliente(handler))
    assert str(pedidos[0].url) == f"https://www.virustotal.com/api/v3/files/{SHA_EICAR}"


def test_404_significa_desconhecido_e_devolve_none():
    erro_404 = {"error": {"code": "NotFoundError", "message": "not found"}}
    assert consultar_dominio("a-b-c.com", CHAVE, _cliente(_json(erro_404, 404))) is None
    assert consultar_arquivo(SHA_EICAR, CHAVE, _cliente(_json(erro_404, 404))) is None


@pytest.mark.parametrize("status", [401, 403])
def test_chave_recusada_vira_erro_sem_mostrar_a_chave(status):
    corpo = {"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}}
    with pytest.raises(ServicoExternoError) as erro:
        consultar_dominio("google.com", CHAVE, _cliente(_json(corpo, status)))
    assert CHAVE not in erro.value.mensagem
    assert "VIRUSTOTAL_API_KEY" in erro.value.mensagem


def test_limite_excedido_429_vira_erro():
    with pytest.raises(ServicoExternoError) as erro:
        consultar_dominio("google.com", CHAVE, _cliente(_json({"error": {}}, 429)))
    assert "limite" in erro.value.mensagem.lower()


def test_erro_do_servidor_vira_erro():
    with pytest.raises(ServicoExternoError):
        consultar_dominio("google.com", CHAVE, _cliente(lambda r: httpx.Response(500)))


def test_resposta_que_nao_e_json_vira_erro():
    with pytest.raises(ServicoExternoError):
        consultar_dominio("google.com", CHAVE, _cliente(lambda r: httpx.Response(200, text="<html>")))


def test_json_que_nao_e_objeto_vira_erro():
    with pytest.raises(ServicoExternoError):
        consultar_dominio("google.com", CHAVE, _cliente(_json([1, 2, 3])))


def test_timeout_vira_erro():
    def handler(request):
        raise httpx.ReadTimeout("demorou", request=request)

    with pytest.raises(ServicoExternoError):
        consultar_dominio("google.com", CHAVE, _cliente(handler))


def test_sem_estatisticas_devolve_none():
    assert consultar_dominio("a.com", CHAVE, _cliente(_json({"data": {"attributes": {}}}))) is None


def test_valores_estranhos_nas_estatisticas_viram_zero():
    dados = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": "muitos", "suspicious": -5, "harmless": True, "undetected": 4}}}}
    assert consultar_dominio("a.com", CHAVE, _cliente(_json(dados))) == ReputacaoVT(0, 0, 0, 4)


@pytest.mark.parametrize("nome", ["a b.com", "a.com/x", "", "../x"])
def test_dominio_estranho_e_recusado_sem_consultar(nome):
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json=GOOGLE)

    with pytest.raises(ServicoExternoError):
        consultar_dominio(nome, CHAVE, _cliente(handler))
    assert chamadas == []


@pytest.mark.parametrize("sha", ["zzz", "abc", "g" * 64, "", SHA_EICAR + "0", "../" + SHA_EICAR])
def test_hash_invalido_e_recusado_sem_consultar(sha):
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json=EICAR)

    with pytest.raises(ServicoExternoError):
        consultar_arquivo(sha, CHAVE, _cliente(handler))
    assert chamadas == []


# --- Limitador ------------------------------------------------------------------


class Relogio:
    def __init__(self):
        self.agora = 1000.0

    def __call__(self):
        return self.agora


def test_limitador_permite_4_por_minuto_e_barra_a_quinta():
    relogio = Relogio()
    lim = LimitadorVT(relogio=relogio)
    assert [lim.tentar_usar() for _ in range(5)] == [True, True, True, True, False]


def test_limitador_libera_de_novo_depois_de_um_minuto():
    relogio = Relogio()
    lim = LimitadorVT(relogio=relogio)
    for _ in range(4):
        lim.tentar_usar()
    relogio.agora += 59
    assert lim.tentar_usar() is False
    relogio.agora += 2
    assert lim.tentar_usar() is True


def test_limitador_respeita_o_teto_diario_e_zera_no_dia_seguinte():
    relogio = Relogio()
    dia = {"hoje": date(2026, 10, 22)}
    lim = LimitadorVT(por_minuto=1000, por_dia=3, relogio=relogio, hoje=lambda: dia["hoje"])
    assert [lim.tentar_usar() for _ in range(4)] == [True, True, True, False]
    dia["hoje"] = date(2026, 10, 23)
    assert lim.tentar_usar() is True


def test_limitador_aguenta_varias_threads_sem_passar_do_limite():
    lim = LimitadorVT(relogio=Relogio())
    resultados = []
    trava = threading.Lock()

    def usar():
        ok = lim.tentar_usar()
        with trava:
            resultados.append(ok)

    threads = [threading.Thread(target=usar) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert resultados.count(True) == 4


# --- Cache e limite local --------------------------------------------------------


def test_segunda_consulta_do_mesmo_dominio_usa_o_cache():
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(200, json=GOOGLE)

    cliente = _cliente(handler)
    primeira = reputacao_do_dominio("google.com", CHAVE, cliente)
    segunda = reputacao_do_dominio("google.com", CHAVE, cliente)
    assert primeira == segunda
    assert len(pedidos) == 1


def test_dominio_desconhecido_tambem_fica_no_cache():
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    cliente = _cliente(handler)
    assert reputacao_do_dominio("novo-golpe.xyz", CHAVE, cliente) is None
    assert reputacao_do_dominio("novo-golpe.xyz", CHAVE, cliente) is None
    assert len(pedidos) == 1


def test_falha_nao_vai_para_o_cache():
    estado = {"falhar": True}

    def handler(request):
        if estado["falhar"]:
            return httpx.Response(500)
        return httpx.Response(200, json=GOOGLE)

    cliente = _cliente(handler)
    with pytest.raises(ServicoExternoError):
        reputacao_do_dominio("google.com", CHAVE, cliente)
    estado["falhar"] = False
    assert reputacao_do_dominio("google.com", CHAVE, cliente).total == 92


def test_limite_local_barra_a_consulta_sem_chamar_a_rede(monkeypatch):
    monkeypatch.setattr(vt, "_limitador", LimitadorVT(por_minuto=0))
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json=GOOGLE)

    with pytest.raises(ServicoExternoError):
        reputacao_do_dominio("google.com", CHAVE, _cliente(handler))
    assert chamadas == []


def test_reputacao_do_arquivo_tambem_usa_cache():
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(200, json=EICAR)

    cliente = _cliente(handler)
    reputacao_do_arquivo(SHA_EICAR, CHAVE, cliente)
    reputacao_do_arquivo(SHA_EICAR, CHAVE, cliente)
    assert len(pedidos) == 1


# --- Sinal de domínio ----------------------------------------------------------------


@pytest.mark.parametrize("marcados", [0, 1, 2])
def test_poucos_motores_nao_geram_sinal(marcados):
    # google.com tem 1 motor marcando: não podemos acusar o Google por isso
    assert sinal_de_dominio("google.com", ReputacaoVT(malicioso=marcados, inofensivo=60, nao_detectado=30)) is None


@pytest.mark.parametrize(
    "marcados, pontos, forte",
    [(3, 15, False), (5, 15, False), (6, 30, False), (9, 30, False), (10, 45, True), (40, 45, True)],
)
def test_faixas_de_pontuacao_do_sinal(marcados, pontos, forte):
    sinal = sinal_de_dominio("golpe.xyz", ReputacaoVT(malicioso=marcados, inofensivo=40, nao_detectado=30))
    assert sinal.codigo == "virustotal_malicioso"
    assert sinal.pontos == pontos
    assert sinal.forte is forte
    assert sinal.origem == "virustotal"


def test_motores_suspeitos_tambem_contam():
    sinal = sinal_de_dominio("golpe.xyz", ReputacaoVT(malicioso=2, suspeito=1, inofensivo=60))
    assert sinal.pontos == 15


def test_descricao_tem_numeros_e_nao_afirma_certeza():
    sinal = sinal_de_dominio("golpe.xyz", ReputacaoVT(malicioso=12, inofensivo=60, nao_detectado=20))
    assert "12" in sinal.descricao and "92" in sinal.descricao and "golpe.xyz" in sinal.descricao
    assert "não uma certeza" in sinal.descricao


def test_sem_motores_analisando_nao_gera_sinal():
    assert sinal_de_dominio("golpe.xyz", ReputacaoVT()) is None


# --- analisar_virustotal -----------------------------------------------------------------


@pytest.fixture
def ligar(monkeypatch):
    def _ligar(handler, chave=CHAVE, osint="true"):
        monkeypatch.setenv("OSINT_ATIVADO", osint)
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", chave)
        get_settings.cache_clear()
        monkeypatch.setattr(vt, "criar_cliente", lambda *a, **k: _cliente(handler))

    return _ligar


class Rede:
    def __init__(self, malicioso=12, status=200):
        self.malicioso, self.status = malicioso, status
        self.pedidos: list[httpx.Request] = []
        self._trava = threading.Lock()

    def __call__(self, request):
        with self._trava:
            self.pedidos.append(request)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"code": "x"}})
        return httpx.Response(200, json=_stats(malicioso=self.malicioso))

    def caminhos(self):
        return sorted(p.url.path for p in self.pedidos)


def test_sem_chave_nao_consulta_nada(ligar):
    rede = Rede()
    ligar(rede, chave="")
    assert analisar_virustotal("pague em http://golpe-novo.xyz") == []
    assert rede.pedidos == []


def test_com_osint_desligado_nao_consulta_nada(ligar):
    rede = Rede()
    ligar(rede, osint="false")
    assert analisar_virustotal("pague em http://golpe-novo.xyz") == []
    assert rede.pedidos == []


def test_dominio_marcado_por_muitos_motores_gera_sinal_forte(ligar):
    rede = Rede(malicioso=12)
    ligar(rede)
    sinais = analisar_virustotal("pague em http://golpe-novo.xyz/pagar?cpf=123")
    assert [s.codigo for s in sinais] == ["virustotal_malicioso"]
    assert sinais[0].forte is True
    assert rede.caminhos() == ["/api/v3/domains/golpe-novo.xyz"]  # só o domínio, sem caminho nem parâmetros


def test_dominio_limpo_nao_gera_sinal(ligar):
    ligar(Rede(malicioso=0))
    assert analisar_virustotal("veja http://loja-normal.com.br") == []


def test_dominio_oficial_e_encurtador_nao_sao_consultados(ligar):
    rede = Rede()
    ligar(rede)
    assert analisar_virustotal("https://www.claro.com.br e https://bit.ly/abc") == []
    assert rede.pedidos == []


def test_consulta_no_maximo_2_dominios(ligar):
    rede = Rede()
    ligar(rede)
    analisar_virustotal("http://golpe-a.xyz http://golpe-b.xyz http://golpe-c.xyz http://golpe-d.xyz")
    assert len(rede.pedidos) == 2


@pytest.mark.parametrize("status", [401, 429, 500])
def test_falha_do_servico_devolve_lista_vazia_sem_erro(ligar, status):
    ligar(Rede(status=status))
    assert analisar_virustotal("http://golpe-novo.xyz") == []


def test_erro_inesperado_nao_derruba(ligar, monkeypatch):
    ligar(Rede())

    def explode(*_a, **_k):
        raise RuntimeError("bug qualquer")

    monkeypatch.setattr(vt, "consultar_dominio", explode)
    assert analisar_virustotal("http://golpe-novo.xyz") == []