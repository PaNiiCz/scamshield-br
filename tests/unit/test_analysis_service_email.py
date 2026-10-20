"""Testes da integração do analisador de cabeçalhos no orquestrador (Etapa 7)."""

from backend.core.models import MensagemEntrada, NivelRisco
from backend.services.analysis_service import analisar_mensagem

CABECALHO_GOLPE = (
    "Authentication-Results: mx.google.com;\n"
    " dkim=fail header.i=@claro-fatura.xyz;\n"
    " spf=fail smtp.mailfrom=suporte@claro-fatura.xyz;\n"
    " dmarc=fail header.from=claro-fatura.xyz\n"
    "From: Claro Atendimento <suporte@claro-fatura.xyz>\n"
)


def _codigos(resultado):
    return [s.codigo for s in resultado.sinais]


def test_email_com_cabecalho_falso_ganha_sinais_do_cabecalho():
    r = analisar_mensagem(
        MensagemEntrada(
            texto="Olá, segue o aviso da sua conta.",
            canal="email",
            cabecalhos_email=CABECALHO_GOLPE,
        )
    )
    codigos = _codigos(r)
    assert "remetente_spf_falhou" in codigos
    assert "dkim_falhou" in codigos
    assert "dmarc_falhou" in codigos
    assert r.nivel == NivelRisco.VERMELHO


def test_sinais_do_cabecalho_aparecem_uma_unica_vez():
    r = analisar_mensagem(
        MensagemEntrada(
            texto="Olá, segue o aviso da sua conta.",
            canal="email",
            cabecalhos_email=CABECALHO_GOLPE,
        )
    )
    codigos = _codigos(r)
    assert len(codigos) == len(set(codigos))  # nada duplicado
    # Só do cabeçalho: 25 + 20 + 20 + 30 + 30 + 10 = 135, limitado a 100
    assert r.pontuacao == 100


def test_cabecalho_legitimo_nao_muda_o_resultado_do_corpo():
    sem = analisar_mensagem(
        MensagemEntrada(texto="Sua fatura está disponível.", canal="email")
    )
    com = analisar_mensagem(
        MensagemEntrada(
            texto="Sua fatura está disponível.",
            canal="email",
            cabecalhos_email=(
                "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\n"
                "From: Claro <faturas@claro.com.br>\n"
            ),
        )
    )
    assert com.pontuacao == sem.pontuacao
    assert com.sinais == sem.sinais


def test_cabecalhos_sao_ignorados_fora_do_canal_email():
    r = analisar_mensagem(
        MensagemEntrada(
            texto="Oi, tudo bem? Vamos almoçar amanhã?",
            canal="whatsapp",
            cabecalhos_email=CABECALHO_GOLPE,
        )
    )
    assert r.nivel == NivelRisco.VERDE
    assert r.sinais == []


def test_cabecalho_lixo_nao_derruba_a_analise():
    r = analisar_mensagem(
        MensagemEntrada(
            texto="Oi, tudo bem? Vamos almoçar amanhã?",
            canal="email",
            cabecalhos_email="isto nao e cabecalho %%%",
        )
    )
    assert _codigos(r) == ["cabecalhos_invalidos"]
    assert r.pontuacao == 5
    assert r.nivel == NivelRisco.VERDE