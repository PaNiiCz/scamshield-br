"""Testes do network_lookup (Etapa 8, parte 3): DNS-over-HTTPS, ASN e contato
de abuso. As respostas de exemplo seguem o formato REAL visto na verificação.
Nenhum teste usa a internet."""

import threading

import httpx
import pytest

from backend.core.config import get_settings
from backend.core.errors import ServicoExternoError
from backend.core.models import MensagemEntrada
from backend.osint import network_lookup, osint_service
from backend.osint.network_lookup import (
    InfoRede,
    consultar_abuso,
    consultar_asn,
    investigar_rede,
    resolver_dominio,
)
from backend.services.analysis_service import analisar_mensagem

# --- Respostas de exemplo (formato real) -------------------------------------

DOH_CLARO = {
    "Status": 0,
    "Answer": [
        {"name": "www.claro.com.br", "type": 5, "TTL": 231, "data": "prd-cdn-claro.clarobrasil.mobi."},
        {"name": "prd-cdn-claro.clarobrasil.mobi", "type": 5, "TTL": 53, "data": "d3d5njhgp3sk29.cloudfront.net."},
        {"name": "d3d5njhgp3sk29.cloudfront.net", "type": 1, "TTL": 53, "data": "108.158.137.40"},
        {"name": "d3d5njhgp3sk29.cloudfront.net", "type": 1, "TTL": 53, "data": "108.158.137.57"},
        {"name": "d3d5njhgp3sk29.cloudfront.net", "type": 1, "TTL": 53, "data": "108.158.137.77"},
        {"name": "d3d5njhgp3sk29.cloudfront.net", "type": 1, "TTL": 53, "data": "108.158.137.42"},
    ],
}
DOH_UM_IP = {"Status": 0, "Answer": [{"name": "x.xyz", "type": 1, "TTL": 60, "data": "3.163.236.182"}]}
DOH_NAO_EXISTE = {"Status": 3}

RIPE_AMAZON = {
    "status": "ok",
    "data": {
        "resource": "3.163.236.0/24",
        "block": {"resource": "3.0.0.0/8", "desc": "Administered by ARIN"},
        "asns": [{"asn": 16509, "holder": "AMAZON-02 - Amazon.com, Inc."}],
    },
}

RDAP_AMAZON = {
    "name": "AMAZON-CF",
    "startAddress": "3.160.0.0",
    "endAddress": "3.163.255.255",
    "entities": [
        {
            "handle": "AEA8-ARIN",
            "roles": ["abuse"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["email", {}, "text", "trustandsafety@support.aws.com"]],
            ],
        }
    ],
}

RDAP_GOOGLE_ANINHADO = {
    "name": "GOGL",
    "entities": [
        {
            "handle": "GOOGL-2-Z",
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]]],
            "entities": [
                {
                    "handle": "ABUSE5250-ARIN",
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [["version", {}, "text", "4.0"], ["email", {}, "text", "network-abuse@google.com"]],
                    ],
                }
            ],
        }
    ],
}


def _cliente(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def _json(dados, status=200):
    return lambda request: httpx.Response(status, json=dados)


# --- resolver_dominio ---------------------------------------------------------


def test_resolve_seguindo_cname_e_devolve_so_os_ips():
    ips = resolver_dominio("www.claro.com.br", _cliente(_json(DOH_CLARO)))
    assert ips == ["108.158.137.40", "108.158.137.57", "108.158.137.77", "108.158.137.42"]


def test_envia_so_o_nome_do_dominio_ao_servidor_de_dns():
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(200, json=DOH_UM_IP)

    resolver_dominio("golpe-novo.xyz", _cliente(handler))
    assert pedidos[0].url.host == "cloudflare-dns.com"
    assert dict(pedidos[0].url.params) == {"name": "golpe-novo.xyz", "type": "A"}
    assert pedidos[0].headers["accept"] == "application/dns-json"


def test_dominio_inexistente_status_3_devolve_lista_vazia():
    assert resolver_dominio("nao-existe.com", _cliente(_json(DOH_NAO_EXISTE))) == []


def test_sem_resposta_devolve_lista_vazia():
    assert resolver_dominio("a.com", _cliente(_json({"Status": 0}))) == []


def test_ignora_ips_privados_locais_e_lixo():
    dados = {
        "Status": 0,
        "Answer": [
            {"type": 1, "data": "10.0.0.1"},
            {"type": 1, "data": "127.0.0.1"},
            {"type": 1, "data": "192.168.1.5"},
            {"type": 1, "data": "169.254.169.254"},
            {"type": 1, "data": "1.2.3.4/../x"},
            {"type": 1, "data": 12345},
            {"type": 1, "data": "2001:4860:4860::8888"},
            {"type": 1, "data": "8.8.8.8"},
        ],
    }
    assert resolver_dominio("a.com", _cliente(_json(dados))) == ["8.8.8.8"]


def test_nao_repete_ip_e_limita_a_4():
    respostas = [{"type": 1, "data": f"8.8.8.{n}"} for n in (1, 1, 2, 3, 4, 5, 6)]
    ips = resolver_dominio("a.com", _cliente(_json({"Status": 0, "Answer": respostas})))
    assert ips == ["8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4"]


def test_se_cloudflare_falha_usa_o_google():
    hosts = []

    def handler(request):
        hosts.append(request.url.host)
        if request.url.host == "cloudflare-dns.com":
            return httpx.Response(500)
        return httpx.Response(200, json=DOH_UM_IP)

    assert resolver_dominio("a.com", _cliente(handler)) == ["3.163.236.182"]
    assert hosts == ["cloudflare-dns.com", "dns.google"]


def test_se_os_dois_falham_levanta_servico_externo_error():
    with pytest.raises(ServicoExternoError):
        resolver_dominio("a.com", _cliente(lambda r: httpx.Response(503)))


def test_resposta_que_nao_e_json_levanta_erro():
    with pytest.raises(ServicoExternoError):
        resolver_dominio("a.com", _cliente(lambda r: httpx.Response(200, text="<html>")))


def test_timeout_levanta_erro():
    def handler(request):
        raise httpx.ConnectTimeout("demorou", request=request)

    with pytest.raises(ServicoExternoError):
        resolver_dominio("a.com", _cliente(handler))


@pytest.mark.parametrize("nome", ["a b.com", "a.com/x", "", "../x"])
def test_dominio_estranho_e_recusado_sem_consultar(nome):
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json=DOH_UM_IP)

    with pytest.raises(ServicoExternoError):
        resolver_dominio(nome, _cliente(handler))
    assert chamadas == []


# --- consultar_asn ------------------------------------------------------------


def test_asn_le_numero_titular_e_prefixo():
    assert consultar_asn("3.163.236.182", _cliente(_json(RIPE_AMAZON))) == (
        16509,
        "AMAZON-02 - Amazon.com, Inc.",
        "3.163.236.0/24",
    )


def test_asn_envia_so_o_ip():
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(200, json=RIPE_AMAZON)

    consultar_asn("3.163.236.182", _cliente(handler))
    assert pedidos[0].url.host == "stat.ripe.net"
    assert dict(pedidos[0].url.params) == {"resource": "3.163.236.182"}


def test_asn_sem_lista_devolve_so_o_prefixo():
    dados = {"status": "ok", "data": {"resource": "3.163.236.0/24", "asns": []}}
    assert consultar_asn("3.163.236.182", _cliente(_json(dados))) == (None, None, "3.163.236.0/24")


def test_asn_com_status_diferente_de_ok_devolve_tudo_none():
    assert consultar_asn("8.8.8.8", _cliente(_json({"status": "error", "data": {}}))) == (None, None, None)


def test_asn_com_formato_estranho_nao_quebra():
    dados = {"status": "ok", "data": {"resource": "lixo", "asns": [{"asn": "nao-e-numero"}, 5, None]}}
    assert consultar_asn("8.8.8.8", _cliente(_json(dados))) == (None, None, None)


def test_asn_erro_do_servidor_levanta_erro():
    with pytest.raises(ServicoExternoError):
        consultar_asn("8.8.8.8", _cliente(lambda r: httpx.Response(500)))


@pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "nao-e-ip", "", "8.8.8.8/../x", "169.254.169.254"])
def test_asn_recusa_ip_invalido_ou_privado_sem_consultar(ip):
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json=RIPE_AMAZON)

    with pytest.raises(ServicoExternoError):
        consultar_asn(ip, _cliente(handler))
    assert chamadas == []


# --- consultar_abuso ----------------------------------------------------------


def test_abuso_le_nome_da_rede_e_email():
    nome, emails = consultar_abuso("3.163.236.182", _cliente(_json(RDAP_AMAZON)))
    assert nome == "AMAZON-CF"
    assert emails == ("trustandsafety@support.aws.com",)


def test_abuso_encontra_email_em_entidade_aninhada():
    nome, emails = consultar_abuso("8.8.8.8", _cliente(_json(RDAP_GOOGLE_ANINHADO)))
    assert nome == "GOGL"
    assert emails == ("network-abuse@google.com",)


def test_abuso_usa_o_rdap_org_de_ip_e_segue_redirecionamento():
    def handler(request):
        if request.url.host == "rdap.org":
            assert request.url.path == "/ip/3.163.236.182"
            return httpx.Response(302, headers={"location": "https://rdap.arin.net/registry/ip/3.163.236.182"})
        return httpx.Response(200, json=RDAP_AMAZON)

    assert consultar_abuso("3.163.236.182", _cliente(handler))[1] == ("trustandsafety@support.aws.com",)


def test_abuso_ignora_entidades_que_nao_sao_de_abuso():
    dados = {
        "name": "X",
        "entities": [
            {"roles": ["registrant"], "vcardArray": ["vcard", [["email", {}, "text", "dono@exemplo.com"]]]}
        ],
    }
    assert consultar_abuso("8.8.8.8", _cliente(_json(dados))) == ("X", ())


def test_abuso_nao_repete_e_ignora_email_invalido():
    entidade = {
        "roles": ["abuse"],
        "vcardArray": [
            "vcard",
            [
                ["email", {}, "text", "abuso@host.com"],
                ["email", {}, "text", "abuso@host.com"],
                ["email", {}, "text", "isto nao e email"],
                ["email", {}, "text", 123],
            ],
        ],
    }
    assert consultar_abuso("8.8.8.8", _cliente(_json({"name": "X", "entities": [entidade]})))[1] == (
        "abuso@host.com",
    )


def test_abuso_404_devolve_vazio():
    assert consultar_abuso("8.8.8.8", _cliente(lambda r: httpx.Response(404))) == (None, ())


def test_abuso_vcard_quebrado_nao_derruba():
    dados = {"name": "X", "entities": [{"roles": ["abuse"], "vcardArray": "lixo"}, "string-solta", None]}
    assert consultar_abuso("8.8.8.8", _cliente(_json(dados))) == ("X", ())


def test_abuso_erro_do_servidor_levanta_erro():
    with pytest.raises(ServicoExternoError):
        consultar_abuso("8.8.8.8", _cliente(lambda r: httpx.Response(500)))


@pytest.mark.parametrize("ip", ["10.0.0.1", "nao-e-ip", ""])
def test_abuso_recusa_ip_invalido_sem_consultar(ip):
    chamadas = []

    def handler(request):
        chamadas.append(request)
        return httpx.Response(200, json=RDAP_AMAZON)

    with pytest.raises(ServicoExternoError):
        consultar_abuso(ip, _cliente(handler))
    assert chamadas == []


# --- investigar_rede ----------------------------------------------------------


class Rede:
    def __init__(self, doh=DOH_UM_IP, ripe=RIPE_AMAZON, rdap=RDAP_AMAZON, falhar=()):
        self.doh, self.ripe, self.rdap = doh, ripe, rdap
        self.falhar = set(falhar)
        self.pedidos: list[httpx.Request] = []
        self._trava = threading.Lock()

    def __call__(self, request):
        with self._trava:
            self.pedidos.append(request)
        host = request.url.host
        if host in self.falhar:
            return httpx.Response(500)
        if host in ("cloudflare-dns.com", "dns.google"):
            return httpx.Response(200, json=self.doh)
        if host == "stat.ripe.net":
            return httpx.Response(200, json=self.ripe)
        if host == "rdap.org":
            return httpx.Response(200, json=self.rdap)
        raise AssertionError(f"servidor inesperado: {host}")

    def hosts(self):
        return [p.url.host for p in self.pedidos]


@pytest.fixture
def ligar(monkeypatch):
    def _ligar(rede: Rede):
        monkeypatch.setenv("OSINT_ATIVADO", "true")
        get_settings.cache_clear()
        monkeypatch.setattr(
            network_lookup,
            "criar_cliente",
            lambda *a, **k: httpx.Client(transport=httpx.MockTransport(rede), follow_redirects=True),
        )
        return rede

    return _ligar


def test_investiga_dominio_completo(ligar):
    ligar(Rede())
    info = investigar_rede("golpe-novo.xyz")
    assert info == InfoRede(
        dominio="golpe-novo.xyz",
        ips=("3.163.236.182",),
        asn=16509,
        asn_titular="AMAZON-02 - Amazon.com, Inc.",
        prefixo="3.163.236.0/24",
        rede_nome="AMAZON-CF",
        emails_abuso=("trustandsafety@support.aws.com",),
    )


def test_desligado_nao_consulta_nada_e_devolve_info_vazia(monkeypatch):
    criou = []
    monkeypatch.setattr(network_lookup, "criar_cliente", lambda *a, **k: criou.append(1))
    info = investigar_rede("golpe-novo.xyz")
    assert info == InfoRede(dominio="golpe-novo.xyz")
    assert criou == []


def test_dominio_que_nao_resolve_nao_consulta_asn_nem_rdap(ligar):
    rede = ligar(Rede(doh=DOH_NAO_EXISTE))
    info = investigar_rede("nao-existe.xyz")
    assert info == InfoRede(dominio="nao-existe.xyz")
    assert "stat.ripe.net" not in rede.hosts()
    assert "rdap.org" not in rede.hosts()


def test_so_o_primeiro_ip_vai_para_asn_e_rdap_e_so_o_ip(ligar):
    rede = ligar(Rede(doh=DOH_CLARO))
    info = investigar_rede("www.claro.com.br")
    assert info.ips == ("108.158.137.40", "108.158.137.57", "108.158.137.77", "108.158.137.42")
    ripe = [p for p in rede.pedidos if p.url.host == "stat.ripe.net"]
    rdap = [p for p in rede.pedidos if p.url.host == "rdap.org"]
    assert len(ripe) == 1 and len(rdap) == 1
    assert dict(ripe[0].url.params) == {"resource": "108.158.137.40"}
    assert rdap[0].url.path == "/ip/108.158.137.40"


def test_falha_do_asn_mantem_o_contato_de_abuso(ligar):
    ligar(Rede(falhar={"stat.ripe.net"}))
    info = investigar_rede("golpe-novo.xyz")
    assert info.asn is None and info.asn_titular is None
    assert info.emails_abuso == ("trustandsafety@support.aws.com",)
    assert info.ips == ("3.163.236.182",)


def test_falha_do_rdap_mantem_o_asn(ligar):
    ligar(Rede(falhar={"rdap.org"}))
    info = investigar_rede("golpe-novo.xyz")
    assert info.asn == 16509
    assert info.emails_abuso == ()


def test_falha_de_tudo_devolve_info_vazia_sem_erro(ligar):
    ligar(Rede(falhar={"cloudflare-dns.com", "dns.google", "stat.ripe.net", "rdap.org"}))
    assert investigar_rede("golpe-novo.xyz") == InfoRede(dominio="golpe-novo.xyz")


def test_dominio_estranho_devolve_info_vazia_sem_consultar(ligar):
    rede = ligar(Rede())
    assert investigar_rede("a b.com").ips == ()
    assert rede.pedidos == []


def test_segunda_chamada_usa_o_cache(ligar):
    rede = ligar(Rede())
    primeira = investigar_rede("golpe-novo.xyz")
    total = len(rede.pedidos)
    assert total == 3  # DNS + ASN + RDAP
    assert investigar_rede("golpe-novo.xyz") == primeira
    assert len(rede.pedidos) == total


def test_resultado_incompleto_por_falha_nao_vai_para_o_cache(ligar):
    rede = ligar(Rede(falhar={"stat.ripe.net", "rdap.org"}))
    investigar_rede("golpe-novo.xyz")
    rede.falhar.clear()
    info = investigar_rede("golpe-novo.xyz")
    assert info.asn == 16509


def test_analise_normal_nao_usa_o_network_lookup(ligar, monkeypatch):
    # O /analisar não pode ficar mais lento nem consultar IPs: o network_lookup
    # é só para a denúncia (Etapa 10).
    rede = ligar(Rede())
    monkeypatch.setattr(
        osint_service,
        "criar_cliente",
        lambda *a, **k: httpx.Client(transport=httpx.MockTransport(rede), follow_redirects=True),
    )
    analisar_mensagem(MensagemEntrada(texto="Pague agora: http://golpe-novo.xyz"))
    assert "cloudflare-dns.com" not in rede.hosts()
    assert "dns.google" not in rede.hosts()
    assert "stat.ripe.net" not in rede.hosts()
    assert not any(p.url.path.startswith("/ip/") for p in rede.pedidos)