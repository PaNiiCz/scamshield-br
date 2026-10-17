from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_saude():
    resposta = client.get("/saude")
    assert resposta.status_code == 200
    assert resposta.json() == {"status": "ok"}


def test_analisar_golpe_devolve_vermelho_com_sinais():
    resposta = client.post(
        "/analisar",
        json={
            "texto": "CLARO: sua fatura está em atraso e sua linha será "
            "bloqueada hoje! Pague via PIX imediatamente.",
            "canal": "whatsapp",
        },
    )
    assert resposta.status_code == 200
    dados = resposta.json()
    assert dados["nivel"] == "vermelho"
    assert dados["pontuacao"] >= 60
    assert len(dados["sinais"]) >= 4
    for sinal in dados["sinais"]:
        assert sinal["codigo"]
        assert sinal["descricao"]


def test_analisar_mensagem_inocente_devolve_verde():
    resposta = client.post("/analisar", json={"texto": "Oi, tudo bem?"})
    assert resposta.status_code == 200
    assert resposta.json()["nivel"] == "verde"


def test_texto_vazio_e_recusado():
    resposta = client.post("/analisar", json={"texto": "    "})
    assert resposta.status_code == 422


def test_canal_invalido_e_recusado():
    resposta = client.post("/analisar", json={"texto": "oi", "canal": "telegrama"})
    assert resposta.status_code == 422


def test_texto_gigante_e_recusado():
    resposta = client.post("/analisar", json={"texto": "a" * 10_001})
    assert resposta.status_code == 422