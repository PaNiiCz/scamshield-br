"""Testes da Etapa 7.5: avisos legítimos não podem virar falso positivo,
e golpes disfarçados de aviso não podem escapar."""

import pytest

from backend.analyzers.rules import analisar_regras


def _dados_sensiveis(texto: str):
    return [s for s in analisar_regras(texto) if s.codigo == "pedido_dados_sensiveis"]


# --- mensagens legítimas: NÃO podem gerar o sinal --------------------------

LEGITIMAS = [
    "Seu código de verificação é 123456. Não compartilhe com ninguém.",
    "Código de segurança: 482913. Nunca compartilhe este código.",
    "123456 é o seu código de verificação. Se não foi você, ignore.",
    "Use o código 556677 para entrar no app.",
    "Atenção: o banco nunca pede sua senha por mensagem.",
    "Nunca pedimos seu token, senha ou dados do cartão por WhatsApp.",
    "Se alguém pedir seu código de verificação, não compartilhe.",
    "Nenhum funcionário pedirá sua senha.",
    "Não informe o código de verificação a ninguém.",
    "Jamais envie sua senha ou o número do cartão por mensagem.",
]


@pytest.mark.parametrize("texto", LEGITIMAS)
def test_aviso_legitimo_nao_dispara_pedido_de_dados(texto):
    assert _dados_sensiveis(texto) == []


# --- golpes: CONTINUAM sendo sinal forte -----------------------------------

GOLPES = [
    "Informe o código que enviamos por SMS",
    "Qual é o código de verificação que chegou no seu celular?",
    "Digite sua senha para desbloquear a conta",
    "Envie a foto do documento e a selfie",
    "Seu código é 123456. Me passa o código agora.",
    # Golpista copiando o tom de aviso para enganar o filtro:
    "Não compartilhe com ninguém, mas informe o código para mim",
    "Não compartilhe com ninguém. Envie a foto do documento.",
    "Nunca pedimos senha, mas agora precisamos da sua senha para confirmar",
    "Seu código de verificação é 123456. Não compartilhe com ninguém. "
    "Me manda o código que chegou.",
]


@pytest.mark.parametrize("texto", GOLPES)
def test_golpe_continua_sendo_sinal_forte(texto):
    sinais = _dados_sensiveis(texto)
    assert len(sinais) == 1
    assert sinais[0].forte is True
    assert sinais[0].pontos == 30


# --- desempenho: entrada gigante e hostil não pode travar a análise --------


@pytest.mark.parametrize(
    "texto",
    [
        "nenhum " + "aaa " * 2500,
        "se alguem " + "x " * 4900,
        "nao compartilhe " + "a " * 4900,
        "se alguem pedir " * 600,
    ],
)
def test_texto_gigante_nao_trava_as_regras(texto):
    import time

    inicio = time.perf_counter()
    analisar_regras(texto[:10_000])
    assert time.perf_counter() - inicio < 1.0