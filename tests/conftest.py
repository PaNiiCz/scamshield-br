"""Configuração compartilhada dos testes.

Garante que NENHUM teste acesse a internet por acidente: o OSINT fica
desligado e, mesmo que alguém o ligue, o cliente HTTP padrão é trocado
por um que recusa qualquer conexão.
"""

import httpx
import pytest

from backend.core.config import get_settings
from backend.osint import osint_service


def _cliente_sem_rede(*_args, **_kwargs) -> httpx.Client:
    def recusar(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("rede bloqueada nos testes", request=request)

    return httpx.Client(transport=httpx.MockTransport(recusar))


@pytest.fixture(autouse=True)
def osint_desligado_e_sem_rede(monkeypatch):
    monkeypatch.setenv("OSINT_ATIVADO", "false")
    get_settings.cache_clear()
    monkeypatch.setattr(osint_service, "criar_cliente", _cliente_sem_rede)
    osint_service.limpar_cache()
    yield
    get_settings.cache_clear()
    osint_service.limpar_cache()