"""Verificação REAL das APIs de rede do OSINT (Etapa 8, parte 3).

Só consulta IPs e domínios públicos e inofensivos (8.8.8.8, o IP da
claro.com.br, example.com). Nunca consulta domínio suspeito.
"""

import json
import time

import httpx

TIMEOUT = 20.0
CLIENTE = httpx.Client(
    timeout=TIMEOUT,
    follow_redirects=True,
    headers={"User-Agent": "ScamShieldBR-verificacao/0.1"},
)


def consultar(titulo: str, url: str, **kwargs) -> httpx.Response | None:
    print(f"\n=== {titulo} ===")
    print(f"URL: {url}")
    inicio = time.perf_counter()
    try:
        resp = CLIENTE.get(url, **kwargs)
    except httpx.HTTPError as erro:
        print(f"FALHOU: {type(erro).__name__}: {erro}")
        return None
    duracao = time.perf_counter() - inicio
    print(f"status={resp.status_code} tempo={duracao:.2f}s")
    print(f"tipo={resp.headers.get('content-type')}")
    print(f"URL final: {resp.url}")
    return resp


def json_ou_none(resp: httpx.Response | None):
    if resp is None:
        return None
    try:
        return resp.json()
    except ValueError:
        print(f"Resposta não é JSON. Começo: {resp.text[:150]!r}")
        return None


def achar_contatos_de_abuso(dados: dict) -> list:
    """Procura entidades com papel 'abuse' e mostra o e-mail do vcard."""
    achados = []

    def varrer(entidades):
        for ent in entidades or []:
            if "abuse" in (ent.get("roles") or []):
                vcard = ent.get("vcardArray")
                emails = []
                if isinstance(vcard, list) and len(vcard) > 1:
                    for campo in vcard[1]:
                        if campo and campo[0] == "email":
                            emails.append(campo[3])
                achados.append({"handle": ent.get("handle"), "emails": emails})
            varrer(ent.get("entities"))

    varrer(dados.get("entities"))
    return achados


def rdap_ip(titulo: str, ip: str) -> None:
    dados = json_ou_none(consultar(titulo, f"https://rdap.org/ip/{ip}"))
    if isinstance(dados, dict):
        print("chaves:", sorted(dados.keys()))
        print("nome:", dados.get("name"), "| país:", dados.get("country"))
        print("faixa:", dados.get("startAddress"), "->", dados.get("endAddress"))
        print("contatos de abuso:", achar_contatos_de_abuso(dados))


def ripestat(titulo: str, ip: str) -> None:
    dados = json_ou_none(
        consultar(titulo, "https://stat.ripe.net/data/prefix-overview/data.json",
                  params={"resource": ip})
    )
    if isinstance(dados, dict):
        print("status:", dados.get("status"))
        corpo = dados.get("data")
        if isinstance(corpo, dict):
            print("resource:", corpo.get("resource"), "| block:", corpo.get("block"))
            print("asns:", json.dumps(corpo.get("asns"), ensure_ascii=False)[:300])


def doh(titulo: str, nome: str, tipo: str = "A") -> None:
    dados = json_ou_none(
        consultar(titulo, "https://cloudflare-dns.com/dns-query",
                  params={"name": nome, "type": tipo},
                  headers={"accept": "application/dns-json"})
    )
    if isinstance(dados, dict):
        print("Status:", dados.get("Status"), "| Answer:", dados.get("Answer"))


def main() -> None:
    rdap_ip("1. RDAP de IP (8.8.8.8, Google)", "8.8.8.8")
    rdap_ip("2. RDAP de IP (3.163.236.182, o IP da claro.com.br)", "3.163.236.182")
    ripestat("3. RIPEstat (8.8.8.8)", "8.8.8.8")
    ripestat("4. RIPEstat (3.163.236.182)", "3.163.236.182")
    doh("5. DoH de domínio que NÃO existe", "scamshield-teste-inexistente-98765.com")
    doh("6. DoH de domínio com CNAME (www.claro.com.br)", "www.claro.com.br")
    print("\nFim. Cole TODA esta saída no chat.")


if __name__ == "__main__":
    main()