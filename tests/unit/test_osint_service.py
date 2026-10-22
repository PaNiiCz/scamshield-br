"""Testes do serviço de OSINT (Etapa 8): escolha dos domínios, paralelismo,
cache, falhas e privacidade. Nenhum teste usa a internet."""

import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from backend.core.config import Settings, get_settings
from backend.osint import osint_service
from backend.osint.http_client import criar_cliente
from backend.osint.osint_service import analisar_osint, selecionar_dominios


def _rdap_recente(dias: int = 5) -> dict:
    data = (datetime.now(timezone.utc) - timedelta(days=dias)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"events": [{"eventAction": "registration", "eventDate": data}]}


class Rede:
    """Rede falsa: guarda todos os pedidos e responde por servidor."""

    def __init__(self, rdap=None, historico=None, atraso=0.0, falhar=()):
        self.rdap = rdap if rdap is not None else _rdap_recente()
        self.historico = historico if historico is not None else {"archived_snapshots": {}}
        self.atraso = atraso
        self.falhar = set(falhar)
        self.pedidos: list[httpx.Request] = []
        self._trava = threading.Lock()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._trava:
            self.pedidos.append(request)
        if self.atraso:
            time.sleep(self.atraso)
        host = request.url.host
        if host in self.falhar:
            return httpx.Response(500)
        if host in ("rdap.registro.br", "rdap.org"):
            return httpx.Response(200, json=self.rdap)
        if host == "archive.org":
            return httpx.Response(200, json=self.historico)
        raise AssertionError(f"servidor inesperado: {host}")

    def dominios_consultados(self) -> set[str]:
        achados = set()
        for p in self.pedidos:
            if p.url.host == "archive.org":
                achados.add(p.url.params["url"])
            else:
                achados.add(p.url.path.rsplit("/", 1)[-1])
        return achados


@pytest.fixture
def ligar(monkeypatch):
    def _ligar(rede: Rede, timeout: str = "5"):
        monkeypatch.setenv("OSINT_ATIVADO", "true")
        monkeypatch.setenv("OSINT_TIMEOUT_SEGUNDOS", timeout)
        get_settings.cache_clear()
        monkeypatch.setattr(
            osint_service,
            "criar_cliente",
            lambda *a, **k: httpx.Client(
                transport=httpx.MockTransport(rede), follow_redirects=True
            ),
        )
        return rede

    return _ligar


def _codigos(sinais):
    return [s.codigo for s in sinais]


# --- Configuração -----------------------------------------------------------


def test_padroes_do_settings(monkeypatch):
    monkeypatch.delenv("OSINT_ATIVADO", raising=False)
    s = Settings(_env_file=None)
    assert s.osint_ativado is True
    assert s.osint_timeout_segundos == 5.0
    assert s.osint_max_dominios == 3


def test_cliente_http_tem_timeout_curto_e_segue_redirecionamento():
    cliente = criar_cliente(5.0)
    assert cliente.timeout.read == 5.0
    assert cliente.timeout.connect == 5.0
    assert cliente.follow_redirects is True
    assert "ScamShield" in cliente.headers["user-agent"]


# --- Escolha dos domínios ---------------------------------------------------


def test_escolhe_dominio_registrado_sem_subdominio_nem_caminho():
    assert selecionar_dominios("veja http://login.golpe-site.xyz/pagar?x=1", 3) == ["golpe-site.xyz"]


def test_nao_escolhe_dominio_oficial():
    assert selecionar_dominios("https://www.claro.com.br/fatura", 3) == []


def test_nao_escolhe_encurtador():
    assert selecionar_dominios("https://bit.ly/abc123 e tinyurl.com/x", 3) == []


def test_nao_escolhe_ip():
    assert selecionar_dominios("http://192.168.0.1/login e http://8.8.8.8/x", 3) == []


def test_nao_escolhe_nome_sem_ponto_nem_sufixo_invalido():
    assert selecionar_dominios("http://localhost:8000/x e http://intranet/y", 3) == []


def test_respeita_o_maximo_de_dominios_na_ordem_do_texto():
    texto = "http://a-golpe.xyz http://b-golpe.xyz http://c-golpe.xyz http://d-golpe.xyz http://e-golpe.xyz"
    assert selecionar_dominios(texto, 3) == ["a-golpe.xyz", "b-golpe.xyz", "c-golpe.xyz"]


def test_nao_repete_dominio():
    assert selecionar_dominios("http://x-golpe.xyz/a http://www.x-golpe.xyz/b", 3) == ["x-golpe.xyz"]


def test_texto_sem_links_nao_escolhe_nada():
    assert selecionar_dominios("Oi, tudo bem? Vamos almoçar amanhã?", 3) == []


# --- Funcionamento ----------------------------------------------------------


def test_desligado_nao_faz_nenhuma_consulta_e_devolve_vazio(monkeypatch):
    # O conftest já deixa o OSINT desligado; aqui conferimos que nada é criado.
    criou = []
    monkeypatch.setattr(osint_service, "criar_cliente", lambda *a, **k: criou.append(1))
    assert analisar_osint("http://golpe-novo.xyz") == []
    assert criou == []


def test_sem_links_nao_faz_consulta(ligar):
    rede = ligar(Rede())
    assert analisar_osint("Oi, tudo bem?") == []
    assert rede.pedidos == []


def test_dominio_novo_sem_historico_gera_os_dois_sinais(ligar):
    ligar(Rede())
    sinais = analisar_osint("pague em http://golpe-novo.xyz")
    assert sorted(_codigos(sinais)) == ["dominio_recente", "site_sem_historico"]
    assert all(s.forte is False for s in sinais)
    assert all(s.origem == "osint" for s in sinais)


def test_dominio_antigo_com_historico_nao_gera_sinal(ligar):
    antigo = {"events": [{"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}]}
    com_historico = {"archived_snapshots": {"closest": {"available": True}}}
    ligar(Rede(rdap=antigo, historico=com_historico))
    assert analisar_osint("http://loja-antiga.com.br") == []


def test_so_o_dominio_e_enviado_a_terceiros(ligar):
    rede = ligar(Rede())
    analisar_osint(
        "Maria, seu CPF 123.456.789-09 está pendente. Pague em "
        "http://golpe-novo.xyz/pagar/cliente123?cpf=12345678909 agora"
    )
    assert rede.pedidos, "deveria ter consultado"
    for pedido in rede.pedidos:
        url = str(pedido.url)
        assert "Maria" not in url
        assert "123456789" not in url and "123.456" not in url
        assert "cliente123" not in url
        assert "pagar" not in url
    assert rede.dominios_consultados() == {"golpe-novo.xyz"}


def test_dominio_oficial_nao_e_consultado(ligar):
    rede = ligar(Rede())
    assert analisar_osint("Sua fatura: https://www.claro.com.br") == []
    assert rede.pedidos == []


def test_consulta_no_maximo_3_dominios(ligar):
    rede = ligar(Rede())
    texto = " ".join(f"http://golpe-{x}.xyz" for x in "abcde")
    analisar_osint(texto)
    assert len(rede.dominios_consultados()) == 3


def test_cada_codigo_aparece_uma_vez_mesmo_com_varios_dominios(ligar):
    ligar(Rede())
    sinais = analisar_osint("http://golpe-a.xyz http://golpe-b.xyz")
    codigos = _codigos(sinais)
    assert len(codigos) == len(set(codigos))


def test_segundo_pedido_do_mesmo_dominio_usa_o_cache(ligar):
    rede = ligar(Rede())
    analisar_osint("http://golpe-novo.xyz")
    primeiros = len(rede.pedidos)
    assert primeiros == 2  # um RDAP + um Archive.org
    segundos = analisar_osint("veja http://golpe-novo.xyz/outro")
    assert len(rede.pedidos) == primeiros
    assert sorted(_codigos(segundos)) == ["dominio_recente", "site_sem_historico"]


def test_cache_nao_guarda_falhas(ligar):
    rede = ligar(Rede(falhar={"archive.org"}))
    analisar_osint("http://golpe-novo.xyz")
    rede.falhar.clear()
    sinais = analisar_osint("http://golpe-novo.xyz")
    assert "site_sem_historico" in _codigos(sinais)


def test_falha_do_rdap_nao_derruba_o_sinal_do_historico(ligar):
    ligar(Rede(falhar={"rdap.org"}))
    sinais = analisar_osint("http://golpe-novo.xyz")
    assert _codigos(sinais) == ["site_sem_historico"]


def test_falha_de_tudo_devolve_lista_vazia_sem_erro(ligar):
    ligar(Rede(falhar={"rdap.org", "archive.org"}))
    assert analisar_osint("http://golpe-novo.xyz") == []


def test_consultas_rodam_em_paralelo(ligar):
    ligar(Rede(atraso=0.3))
    texto = "http://golpe-a.xyz http://golpe-b.xyz http://golpe-c.xyz"
    inicio = time.perf_counter()
    analisar_osint(texto)
    duracao = time.perf_counter() - inicio
    # 6 consultas de 0,3 s em fila levariam 1,8 s
    assert duracao < 1.2


def test_orcamento_de_tempo_corta_servico_lento(ligar):
    ligar(Rede(atraso=2.5), timeout="0.3")
    inicio = time.perf_counter()
    sinais = analisar_osint("http://golpe-novo.xyz")
    duracao = time.perf_counter() - inicio
    assert sinais == []
    assert duracao < 2.0


def test_erro_inesperado_dentro_da_consulta_nao_derruba(ligar, monkeypatch):
    ligar(Rede())

    def explode(*_a, **_k):
        raise RuntimeError("bug qualquer")

    monkeypatch.setattr(osint_service, "consultar_data_registro", explode)
    sinais = analisar_osint("http://golpe-novo.xyz")
    assert _codigos(sinais) == ["site_sem_historico"]