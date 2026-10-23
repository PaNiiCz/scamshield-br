"""Rota de análise de arquivo por hash (Etapa 9).

O arquivo chega como corpo "binário" da requisição (no Postman: Body ->
binary). Lemos em pedaços só para calcular o SHA-256: nada é gravado em disco.
"""

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from backend.core.errors import EntradaInvalidaError
from backend.file_check import file_hash_analyzer as fha

router = APIRouter()


@router.post("/analisar-arquivo", response_model=fha.ResultadoArquivo)
async def analisar_arquivo(request: Request) -> fha.ResultadoArquivo:
    """Recebe os bytes de um arquivo e devolve a análise pelo hash (sem abrir o arquivo)."""
    declarado = request.headers.get("content-length", "")
    if declarado.isdigit() and int(declarado) > fha.LIMITE_BYTES:
        raise HTTPException(status_code=413, detail="O arquivo é maior que o tamanho máximo aceito.")

    calculadora = fha.CalculadoraHash()
    try:
        async for pedaco in request.stream():
            calculadora.adicionar(pedaco)
    except fha.ArquivoGrandeDemaisError as erro:
        raise HTTPException(status_code=413, detail=erro.mensagem) from erro

    sha256, tamanho = calculadora.resultado()
    if tamanho == 0:
        raise EntradaInvalidaError("Nenhum arquivo recebido: envie os bytes no corpo da requisição.")
    return await run_in_threadpool(fha.analisar_hash_do_arquivo, sha256, tamanho)