from backend.analyzers.rules import analisar_regras
from backend.analyzers.scam_types import classificar_tipo
from backend.analyzers.url_analyzer import analisar_urls
from backend.core.models import MensagemEntrada, NivelRisco, TipoGolpe
from backend.services.analysis_service import analisar_mensagem


def tipo(texto: str) -> TipoGolpe | None:
    sinais = analisar_regras(texto) + analisar_urls(texto)
    return classificar_tipo(texto, sinais)


def test_sem_sinais_nao_classifica():
    assert tipo("Oi, tudo bem?") is None


def test_falsa_operadora():
    texto = (
        "CLARO: sua fatura está em atraso e sua linha será bloqueada hoje! "
        "Pague via PIX imediatamente: http://claro-fatura.xyz"
    )
    assert tipo(texto) == TipoGolpe.FALSA_OPERADORA


def test_falso_parente():
    texto = "Oi mãe, mudei de número. Perdi meu celular, salva esse novo número."
    assert tipo(texto) == TipoGolpe.FALSO_PARENTE


def test_boleto():
    texto = "Seu boleto vencido está disponível, use o código de barras para pagar a segunda via"
    assert tipo(texto) == TipoGolpe.BOLETO


def test_conta_bloqueada():
    texto = "Sua conta foi bloqueada. Regularize seu acesso com urgência"
    assert tipo(texto) == TipoGolpe.CONTA_BLOQUEADA


def test_pix():
    assert tipo("Faça um pix de R$ 50 agora") == TipoGolpe.PIX


def test_sinais_fracos_viram_outro():
    assert tipo("Urgente, responda hoje mesmo") == TipoGolpe.OUTRO


def test_desempate_favorece_o_mais_especifico():
    texto = "Oi pai, perdi meu celular. Preciso que faça um pix"
    assert tipo(texto) == TipoGolpe.FALSO_PARENTE


def test_servico_preenche_tipo_e_resumo():
    texto = (
        "CLARO: sua fatura está em atraso e sua linha será bloqueada hoje! "
        "Pague via PIX imediatamente: http://claro-fatura.xyz"
    )
    r = analisar_mensagem(MensagemEntrada(texto=texto))
    assert r.nivel == NivelRisco.VERMELHO
    assert r.pontuacao == 100
    assert r.tipo_golpe == TipoGolpe.FALSA_OPERADORA
    assert "falsa operadora" in r.resumo
    assert "dominio_imitando_marca" in {s.codigo for s in r.sinais}