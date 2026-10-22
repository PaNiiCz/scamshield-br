"""Verificação REAL da API do VirusTotal v3 (Etapa 9, parte 1).

Usa a chave que está no seu arquivo .env (VIRUSTOTAL_API_KEY). A chave
NUNCA é impressa. Só consulta coisas inofensivas e públicas:
- o domínio google.com;
- um domínio que não existe;
- o hash do arquivo de teste EICAR (um texto padrão do mundo todo para testar
  antivírus; não é um vírus de verdade e nada é baixado nem enviado);
- um hash que ninguém conhece;
- uma chave propositalmente falsa, para vermos o formato do erro.

Plano gratuito: 4 consultas por minuto. Por isso o script espera 16 segundos
entre uma consulta e outra (leva cerca de 1 minuto e meio).
"""

import hashlib
import re
import time

import httpx

from backend.core.config import get_settings

BASE = "https://www.virustotal.com/api/v3"
ESPERA_ENTRE_CONSULTAS = 16
SHA256_EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
SHA256_DESCONHECIDO = hashlib.sha256(b"scamshield-br-teste-hash-que-ninguem-conhece-98765").hexdigest()


def consultar(titulo: str, caminho: str, chave: str) -> dict | None:
    print(f"\n=== {titulo} ===")
    print(f"URL: {BASE}{caminho}")
    inicio = time.perf_counter()
    try:
        resp = httpx.get(
            BASE + caminho,
            headers={"x-apikey": chave, "accept": "application/json"},
            timeout=20.0,
        )
    except httpx.HTTPError as erro:
        print(f"FALHOU: {type(erro).__name__}")
        return None
    print(f"status={resp.status_code} tempo={time.perf_counter() - inicio:.2f}s")
    print(f"tipo={resp.headers.get('content-type')}")
    limites = sorted(n for n in resp.headers if re.search(r"rate|quota|limit", n, re.I))
    print("cabecalhos de limite:", limites or "nenhum")
    try:
        dados = resp.json()
    except ValueError:
        print(f"Resposta não é JSON. Começo: {resp.text[:120]!r}")
        return None
    if isinstance(dados, dict) and "error" in dados:
        erro = dados["error"] if isinstance(dados["error"], dict) else {}
        print("erro:", erro.get("code"), "|", str(erro.get("message"))[:150])
    return dados if isinstance(dados, dict) else None


def mostrar_objeto(dados: dict | None) -> None:
    if not dados or "data" not in dados:
        return
    corpo = dados["data"]
    attrs = corpo.get("attributes", {}) if isinstance(corpo, dict) else {}
    print("type:", corpo.get("type"), "| id:", str(corpo.get("id"))[:70])
    print("campos de attributes:", sorted(attrs.keys())[:40])
    print("last_analysis_stats:", attrs.get("last_analysis_stats"))
    for campo in ("reputation", "creation_date", "last_analysis_date", "tld",
                  "type_description", "meaningful_name", "size"):
        if campo in attrs:
            print(f"{campo}:", attrs[campo])
    if "categories" in attrs:
        print("categories:", str(attrs["categories"])[:200])
    if "total_votes" in attrs:
        print("total_votes:", attrs["total_votes"])


def main() -> None:
    chave = get_settings().virustotal_api_key.strip()
    if not chave:
        print("Nenhuma chave encontrada. Coloque VIRUSTOTAL_API_KEY=... no arquivo .env")
        print("(na raiz do projeto) e rode de novo. A chave nunca é mostrada aqui.")
        return
    print("Chave encontrada no .env (não será mostrada).")

    mostrar_objeto(consultar("1. Domínio conhecido (google.com)", "/domains/google.com", chave))
    time.sleep(ESPERA_ENTRE_CONSULTAS)
    mostrar_objeto(
        consultar("2. Domínio que NÃO existe", "/domains/scamshield-teste-inexistente-98765.com", chave)
    )
    time.sleep(ESPERA_ENTRE_CONSULTAS)
    mostrar_objeto(consultar("3. Hash do arquivo de teste EICAR", f"/files/{SHA256_EICAR}", chave))
    time.sleep(ESPERA_ENTRE_CONSULTAS)
    mostrar_objeto(consultar("4. Hash que ninguém conhece", f"/files/{SHA256_DESCONHECIDO}", chave))
    time.sleep(ESPERA_ENTRE_CONSULTAS)
    consultar("5. Chave propositalmente falsa", "/domains/google.com", "0" * 64)

    print("\nFim. Cole TODA esta saída no chat (ela não contém a sua chave).")


if __name__ == "__main__":
    main()