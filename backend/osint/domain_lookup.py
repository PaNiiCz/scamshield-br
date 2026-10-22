"""Idade do domínio via RDAP (Etapa 8). Consulta passiva a fonte pública.

RDAP é o "cartório" dos domínios: diz quando o endereço foi registrado.
NUNCA conectamos ao servidor do domínio investigado; só perguntamos ao
registro público. Para .br usamos o RDAP do Registro.br; para os demais,
o rdap.org, que redireciona ao registro certo.
"""

from datetime import datetime, timezone

import httpx

from backend.core.errors import ServicoExternoError
from backend.core.models import Sinal
from backend.osint.validacao import validar_dominio

ORIGEM = "osint"
RDAP_BR = "https://rdap.registro.br/domain/"
RDAP_GERAL = "https://rdap.org/domain/"


def _extrair_data_registro(dados: object) -> datetime | None:
    if not isinstance(dados, dict):
        return None
    eventos = dados.get("events")
    if not isinstance(eventos, list):
        return None
    for evento in eventos:
        if not isinstance(evento, dict) or evento.get("eventAction") != "registration":
            continue
        texto = evento.get("eventDate")
        if not isinstance(texto, str):
            return None
        try:
            data = datetime.fromisoformat(texto.replace("Z", "+00:00"))
        except ValueError:
            return None
        if data.tzinfo is None:
            data = data.replace(tzinfo=timezone.utc)
        return data
    return None


def consultar_data_registro(dominio: str, cliente: httpx.Client) -> datetime | None:
    """Data de registro do domínio, ou None se o RDAP não souber dizer.

    404 (domínio não encontrado) vira None: "não sei" nunca vira sinal.
    Falha de rede, erro de servidor ou resposta estranha viram
    ServicoExternoError.
    """
    dominio = validar_dominio(dominio)
    base = RDAP_BR if dominio.endswith(".br") else RDAP_GERAL
    try:
        resposta = cliente.get(base + dominio)
    except httpx.HTTPError as erro:
        raise ServicoExternoError("RDAP indisponível no momento.") from erro
    if resposta.status_code == 404:
        return None
    if resposta.status_code != 200:
        raise ServicoExternoError(f"RDAP respondeu com status {resposta.status_code}.")
    try:
        dados = resposta.json()
    except ValueError as erro:
        raise ServicoExternoError("RDAP devolveu uma resposta ilegível.") from erro
    return _extrair_data_registro(dados)


def analisar_idade_dominio(
    dominio: str,
    registrado_em: datetime | None,
    agora: datetime | None = None,
) -> Sinal | None:
    """Sinal 'dominio_recente': menos de 30 dias = 25 pontos; menos de 90 = 15."""
    if registrado_em is None:
        return None
    agora = agora or datetime.now(timezone.utc)
    dias = (agora - registrado_em).days
    if dias < 0 or dias >= 90:
        return None
    pontos = 25 if dias < 30 else 15
    unidade = "dia" if dias == 1 else "dias"
    return Sinal(
        codigo="dominio_recente",
        descricao=(
            f"O domínio {dominio} foi registrado há {dias} {unidade}. "
            "Endereços muito novos são muito usados em golpes."
        ),
        pontos=pontos,
        origem=ORIGEM,
        forte=False,
    )