"""Rotas HTTP do ScamShield BR."""

from fastapi import APIRouter

from backend.core.models import MensagemEntrada, ResultadoAnalise
from backend.services.analysis_service import analisar_mensagem

router = APIRouter()


@router.get("/saude")
def saude() -> dict[str, str]:
    """Rota de verificação: responde se o servidor está de pé."""
    return {"status": "ok"}


@router.post("/analisar", response_model=ResultadoAnalise)
def analisar(mensagem: MensagemEntrada) -> ResultadoAnalise:
    """Recebe uma mensagem suspeita e devolve a análise explicável."""
    return analisar_mensagem(mensagem)