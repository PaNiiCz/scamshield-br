from pathlib import Path

import pytest

from backend.analyzers import text_classifier
from backend.analyzers.text_classifier import (
    CAMINHO_MODELO,
    analisar_ml,
    preparar_texto,
    probabilidade_golpe,
)

SEM_MODELO = not CAMINHO_MODELO.exists()
MOTIVO = "modelo não treinado: rode python -m scripts.train_model"

GOLPE_CLARO = (
    "CLARO: sua fatura está em atraso e sua linha será bloqueada hoje! "
    "Pague via PIX imediatamente: http://claro-fatura.xyz"
)


# ---------- preparo do texto (não precisa do modelo) ----------
def test_preparar_texto_troca_link_e_numero():
    r = preparar_texto("Pague R$ 8.000,00 em http://x.xyz/a")
    assert "linkurl" in r
    assert "num" in r
    assert "8.000" not in r
    assert "http" not in r


def test_preparar_texto_normaliza_acentos_e_maiusculas():
    assert "urgencia" in preparar_texto("URGÊNCIA")


# ---------- sem modelo, o sistema continua funcionando ----------
def test_sem_arquivo_de_modelo_devolve_none(tmp_path: Path):
    inexistente = tmp_path / "nao_existe.joblib"
    assert probabilidade_golpe("qualquer coisa", inexistente) is None


def test_sem_arquivo_de_modelo_nao_gera_sinal(tmp_path: Path):
    inexistente = tmp_path / "nao_existe.joblib"
    assert analisar_ml(GOLPE_CLARO, inexistente) == []


def test_arquivo_de_modelo_corrompido_nao_quebra(tmp_path: Path):
    corrompido = tmp_path / "corrompido.joblib"
    corrompido.write_text("isto não é um modelo")
    assert probabilidade_golpe("oi", corrompido) is None


# ---------- faixas de pontos (simulando a probabilidade) ----------
@pytest.mark.parametrize(
    "probabilidade, pontos_esperados",
    [(0.95, 20), (0.85, 20), (0.70, 10), (0.65, 10)],
)
def test_faixas_de_pontuacao(monkeypatch, probabilidade, pontos_esperados):
    monkeypatch.setattr(
        text_classifier, "probabilidade_golpe", lambda texto, caminho=None: probabilidade
    )
    sinais = analisar_ml("texto qualquer")
    assert len(sinais) == 1
    assert sinais[0].pontos == pontos_esperados
    assert sinais[0].codigo == "ml_texto_suspeito"
    assert sinais[0].origem == "text_classifier"
    assert sinais[0].forte is False


@pytest.mark.parametrize("probabilidade", [0.64, 0.30, 0.0, None])
def test_probabilidade_baixa_ou_ausente_nao_gera_sinal(monkeypatch, probabilidade):
    monkeypatch.setattr(
        text_classifier, "probabilidade_golpe", lambda texto, caminho=None: probabilidade
    )
    assert analisar_ml("texto qualquer") == []


def test_descricao_nao_afirma_certeza(monkeypatch):
    monkeypatch.setattr(
        text_classifier, "probabilidade_golpe", lambda texto, caminho=None: 0.9
    )
    descricao = analisar_ml("x")[0].descricao
    assert "não uma certeza" in descricao


# ---------- com o modelo treinado de verdade ----------
@pytest.mark.skipif(SEM_MODELO, reason=MOTIVO)
def test_modelo_reconhece_golpe_da_claro():
    assert probabilidade_golpe(GOLPE_CLARO) > 0.65


@pytest.mark.skipif(SEM_MODELO, reason=MOTIVO)
def test_modelo_nao_acusa_conversa_normal():
    assert probabilidade_golpe("Oi, tudo bem? Vamos almoçar amanhã?") < 0.5


@pytest.mark.skipif(SEM_MODELO, reason=MOTIVO)
def test_modelo_nao_acusa_fatura_legitima():
    texto = "Sua fatura de outubro já está disponível no app."
    assert probabilidade_golpe(texto) < 0.5


@pytest.mark.skipif(SEM_MODELO, reason=MOTIVO)
def test_probabilidade_fica_entre_zero_e_um():
    p = probabilidade_golpe("Parabéns! Você ganhou um prêmio")
    assert 0.0 <= p <= 1.0


@pytest.mark.skipif(SEM_MODELO, reason=MOTIVO)
def test_pontos_do_ml_sao_limitados_a_20():
    sinais = analisar_ml(GOLPE_CLARO)
    assert sinais
    assert all(s.pontos <= 20 for s in sinais)