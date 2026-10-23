"""Testes da rota POST /analisar-arquivo (Etapa 9). Os bytes do arquivo são
lidos em pedaços, só o SHA-256 é calculado e nada é gravado em disco."""

import os

import httpx
from fastapi.testclient import TestClient

from backend.core.config import get_settings
from backend.file_check import file_hash_analyzer as fha
from backend.main import app
from backend.threat_intel import virustotal_client as vt

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SHA_EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
SHA_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
CABECALHO = {"Content-Type": "application/octet-stream"}


def _enviar(conteudo: bytes, **extra):
    return TestClient(app).post("/analisar-arquivo", content=conteudo, headers=CABECALHO, **extra)


def test_devolve_o_hash_certo_sem_virustotal():
    resposta = _enviar(b"abc")
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["sha256"] == SHA_ABC
    assert corpo["tamanho_bytes"] == 3
    assert corpo["virustotal_consultado"] is False
    assert corpo["nivel"] == "verde"


def test_corpo_vazio_e_recusado():
    assert _enviar(b"").status_code == 422


def test_arquivo_grande_demais_e_recusado_com_413(monkeypatch):
    monkeypatch.setattr(fha, "LIMITE_BYTES", 10)
    assert _enviar(b"x" * 11).status_code == 413


def test_arquivo_no_limite_e_aceito(monkeypatch):
    monkeypatch.setattr(fha, "LIMITE_BYTES", 10)
    assert _enviar(b"x" * 10).status_code == 200


def test_tamanho_declarado_grande_demais_e_recusado_antes_de_ler(monkeypatch):
    monkeypatch.setattr(fha, "LIMITE_BYTES", 10)
    resposta = TestClient(app).post(
        "/analisar-arquivo", content=b"abc", headers={**CABECALHO, "Content-Length": "999999"}
    )
    assert resposta.status_code in (400, 413)


def test_com_virustotal_o_eicar_fica_vermelho(monkeypatch):
    pedidos = []

    def handler(request):
        pedidos.append(request)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {
            "malicious": 66, "suspicious": 0, "harmless": 0, "undetected": 2, "type-unsupported": 7}}}})

    monkeypatch.setenv("OSINT_ATIVADO", "true")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "chave-de-teste-nao-e-real")
    get_settings.cache_clear()
    monkeypatch.setattr(
        vt, "criar_cliente", lambda *a, **k: httpx.Client(transport=httpx.MockTransport(handler))
    )
    resposta = _enviar(EICAR)
    corpo = resposta.json()
    assert corpo["sha256"] == SHA_EICAR
    assert corpo["nivel"] == "vermelho"
    assert corpo["motores_marcaram"] == 66 and corpo["motores_total"] == 68
    assert [p.url.path for p in pedidos] == [f"/api/v3/files/{SHA_EICAR}"]
    assert pedidos[0].content == b""  # o conteúdo do arquivo nunca é enviado


def test_nada_e_gravado_em_disco(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _enviar(b"conteudo qualquer " * 1000)
    assert os.listdir(tmp_path) == []


def test_resposta_nao_repete_o_conteudo_do_arquivo():
    corpo = _enviar(b"SEGREDO-NAO-PODE-VOLTAR").text
    assert "SEGREDO" not in corpo


def test_rota_de_saude_continua_funcionando():
    assert TestClient(app).get("/saude").json() == {"status": "ok"}