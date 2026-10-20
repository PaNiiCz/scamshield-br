"""Verificação REAL das APIs de OSINT (Etapa 8).

Só consulta domínios conhecidos e inofensivos (claro.com.br, cert.br,
example.com). Nunca consulta domínio suspeito. Serve para confirmar o
formato atual das respostas antes de escrevermos o código de verdade.
"""

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


def rdap(titulo: str, url: str) -> None:
    dados = json_ou_none(consultar(titulo, url))
    if isinstance(dados, dict):
        print("chaves:", sorted(dados.keys()))
        print("events:", dados.get("events"))
        print("status:", dados.get("status"))
        if "title" in dados or "errorCode" in dados:
            print("erro:", dados.get("errorCode"), dados.get("title"))


def main() -> None:
    rdap("1. RDAP Registro.br (domínio .br existente)",
         "https://rdap.registro.br/domain/claro.com.br")
    rdap("2. RDAP Registro.br (domínio .br que NÃO existe)",
         "https://rdap.registro.br/domain/scamshield-teste-inexistente-98765.com.br")
    rdap("3. RDAP via rdap.org (domínio .com)",
         "https://rdap.org/domain/example.com")

    resp = consultar("4. crt.sh (Certificate Transparency)",
                     "https://crt.sh/", params={"q": "cert.br", "output": "json"})
    dados = json_ou_none(resp)
    if isinstance(dados, list):
        print("quantidade de certificados:", len(dados))
        if dados:
            print("chaves de um item:", sorted(dados[0].keys()))
            print("menor not_before:", min(i.get("not_before", "?") for i in dados))

    resp = consultar("5. Archive.org (Wayback)",
                     "https://archive.org/wayback/available",
                     params={"url": "claro.com.br"})
    dados = json_ou_none(resp)
    if dados is not None:
        print("resposta:", str(dados)[:400])

    resp = consultar("6. DNS-over-HTTPS Cloudflare",
                     "https://cloudflare-dns.com/dns-query",
                     params={"name": "claro.com.br", "type": "A"},
                     headers={"accept": "application/dns-json"})
    dados = json_ou_none(resp)
    if dados is not None:
        print("Status:", dados.get("Status"), "| Answer:", dados.get("Answer"))

    resp = consultar("7. DNS-over-HTTPS Google",
                     "https://dns.google/resolve",
                     params={"name": "claro.com.br", "type": "A"})
    dados = json_ou_none(resp)
    if dados is not None:
        print("Status:", dados.get("Status"), "| Answer:", dados.get("Answer"))

    print("\nFim. Cole TODA esta saída no chat.")


if __name__ == "__main__":
    main()