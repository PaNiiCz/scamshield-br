"""Testes da API com e-mail e cabeçalhos (Etapa 7)."""

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_analisar_email_com_cabecalhos_pela_api():
    resposta = client.post(
        "/analisar",
        json={
            "texto": "Olá, segue o aviso da sua conta.",
            "canal": "email",
            "cabecalhos_email": (
                "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n"
                "From: Claro Atendimento <suporte@claro-fatura.xyz>\n"
            ),
        },
    )
    assert resposta.status_code == 200
    codigos = [s["codigo"] for s in resposta.json()["sinais"]]
    assert "remetente_spf_falhou" in codigos
    assert "dkim_falhou" in codigos
    assert "dmarc_falhou" in codigos


def test_cabecalhos_gigantes_sao_rejeitados():
    resposta = client.post(
        "/analisar",
        json={
            "texto": "oi",
            "canal": "email",
            "cabecalhos_email": "X-Lixo: a\n" * 5000,
        },
    )
    assert resposta.status_code == 422