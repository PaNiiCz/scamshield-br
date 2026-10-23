"""Configuração compartilhada dos testes.

Garante que NENHUM teste acesse a internet por acidente e que a chave real
do VirusTotal (do seu .env) nunca seja usada nos testes: o OSINT fica
desligado, a chave fica vazia e os clientes HTTP padrão são trocados por
um que recusa qualquer conexão.
"""

import httpx
import pytest

from backend.core.config import get_settings
from backend.osint import network_lookup, osint_service
from backend.threat_intel import virustotal_client


def _cliente_sem_rede(*_args, **_kwargs) -> httpx.Client:
    def recusar(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("rede bloqueada nos testes", request=request)

    return httpx.Client(transport=httpx.MockTransport(recusar))


def _limpar_tudo() -> None:
    get_settings.cache_clear()
    osint_service.limpar_cache()
    network_lookup.limpar_cache()
    virustotal_client.limpar_estado()


@pytest.fixture(autouse=True)
def osint_desligado_e_sem_rede(monkeypatch):
    monkeypatch.setenv("OSINT_ATIVADO", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(osint_service, "criar_cliente", _cliente_sem_rede)
    monkeypatch.setattr(network_lookup, "criar_cliente", _cliente_sem_rede)
    monkeypatch.setattr(virustotal_client, "criar_cliente", _cliente_sem_rede)
    _limpar_tudo()
    yield
    _limpar_tudo()