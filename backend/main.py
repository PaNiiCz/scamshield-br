"""Ponto de entrada do back-end do ScamShield BR."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.api.routes import router
from backend.core.config import get_settings
from backend.core.errors import (
    EntradaInvalidaError,
    ScamShieldError,
    ServicoExternoError,
)

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Análise explicável de golpes digitais em português brasileiro.",
)

app.include_router(router)


# Cada erro nosso vira uma resposta HTTP com o código certo.
@app.exception_handler(EntradaInvalidaError)
async def tratar_entrada_invalida(_: Request, erro: EntradaInvalidaError):
    return JSONResponse(status_code=422, content={"detail": erro.mensagem})


@app.exception_handler(ServicoExternoError)
async def tratar_servico_externo(_: Request, erro: ServicoExternoError):
    return JSONResponse(status_code=503, content={"detail": erro.mensagem})


@app.exception_handler(ScamShieldError)
async def tratar_erro_generico(_: Request, erro: ScamShieldError):
    return JSONResponse(status_code=500, content={"detail": erro.mensagem})