"""Cliente HTTP usado pelas consultas de OSINT."""

import httpx

USER_AGENT = "ScamShieldBR/0.1 (analise passiva de golpes)"


def criar_cliente(timeout_segundos: float = 5.0) -> httpx.Client:
    """Cria um cliente com timeout curto.

    follow_redirects: o rdap.org responde "o dado está em outro servidor"
    (redirecionamento 302) e precisamos seguir. Limitamos a 3 saltos.
    """
    return httpx.Client(
        timeout=timeout_segundos,
        follow_redirects=True,
        max_redirects=3,
        headers={"User-Agent": USER_AGENT},
    )