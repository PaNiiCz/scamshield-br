from backend.core.models import MensagemEntrada, NivelRisco
from backend.services.analysis_service import analisar_mensagem


def test_mensagem_inocente_e_verde_e_sem_sinais():
    r = analisar_mensagem(MensagemEntrada(texto="Oi, vamos almoçar amanhã?"))
    assert r.nivel == NivelRisco.VERDE
    assert r.pontuacao == 0
    assert r.sinais == []
    assert r.resumo != ""


def test_golpe_falsa_operadora_e_vermelho():
    texto = (
        "CLARO: sua fatura está em atraso e sua linha será bloqueada hoje! "
        "Pague via PIX imediatamente: http://claro-fatura.xyz"
    )
    r = analisar_mensagem(MensagemEntrada(texto=texto))
    assert r.nivel == NivelRisco.VERMELHO
    assert r.pontuacao >= 60
    assert len(r.sinais) >= 4


def test_pedido_de_codigo_sozinho_e_pelo_menos_laranja():
    r = analisar_mensagem(
        MensagemEntrada(texto="Informe o código que enviamos por SMS")
    )
    assert r.nivel in (NivelRisco.LARANJA, NivelRisco.VERMELHO)


def test_sinais_vem_ordenados_do_mais_pesado_ao_mais_leve():
    r = analisar_mensagem(
        MensagemEntrada(texto="URGENTE! Sua conta será bloqueada, faça um pix")
    )
    pontos = [s.pontos for s in r.sinais]
    assert pontos == sorted(pontos, reverse=True)


def test_resumo_do_verde_nao_afirma_certeza():
    r = analisar_mensagem(MensagemEntrada(texto="Bom dia!"))
    assert "não garante" in r.resumo