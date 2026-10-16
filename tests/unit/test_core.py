import pytest
from pydantic import ValidationError

from backend.core.config import Settings
from backend.core.errors import (
    EntradaInvalidaError,
    ScamShieldError,
    ServicoExternoError,
)
from backend.core.models import (
    Canal,
    MensagemEntrada,
    NivelRisco,
    ResultadoAnalise,
    Sinal,
)


# ---------- config ----------
def test_config_valores_padrao():
    # _env_file=None ignora o .env real, para o teste ser previsível
    s = Settings(_env_file=None)
    assert s.app_name == "ScamShield BR"
    assert s.limiar_suspeito == 30
    assert s.limiar_alto_risco == 60


# ---------- models ----------
def test_mensagem_valida_usa_whatsapp_por_padrao():
    m = MensagemEntrada(texto="Seu CPF foi bloqueado, pague via PIX")
    assert m.canal == Canal.WHATSAPP


def test_mensagem_remove_espacos_das_pontas():
    m = MensagemEntrada(texto="   oi   ")
    assert m.texto == "oi"


def test_mensagem_vazia_e_recusada():
    with pytest.raises(ValidationError):
        MensagemEntrada(texto="    ")


def test_canal_invalido_e_recusado():
    with pytest.raises(ValidationError):
        MensagemEntrada(texto="oi", canal="telegrama")


def test_pontuacao_fora_do_intervalo_e_recusada():
    with pytest.raises(ValidationError):
        ResultadoAnalise(pontuacao=150, nivel=NivelRisco.VERMELHO)


def test_resultado_com_sinais():
    sinal = Sinal(
        codigo="urgencia_falsa",
        descricao="A mensagem pressiona por ação imediata.",
        pontos=20,
        origem="rules",
    )
    r = ResultadoAnalise(pontuacao=20, nivel=NivelRisco.VERDE, sinais=[sinal])
    assert r.sinais[0].codigo == "urgencia_falsa"
    assert r.sinais[0].forte is False


# ---------- errors ----------
def test_erros_herdam_do_erro_base():
    with pytest.raises(ScamShieldError):
        raise ServicoExternoError("VirusTotal fora do ar")

    erro = EntradaInvalidaError("texto vazio")
    assert erro.mensagem == "texto vazio"