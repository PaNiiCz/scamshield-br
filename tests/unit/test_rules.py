from backend.analyzers.rules import REGRAS, analisar_regras, normalizar


def codigos(texto: str) -> set[str]:
    return {s.codigo for s in analisar_regras(texto)}


# ---------- normalização ----------
def test_normalizar_tira_acento_e_poe_minuscula():
    assert normalizar("URGÊNCIA Ação") == "urgencia acao"


def test_normalizar_tira_caractere_invisivel():
    assert normalizar("urg\u200bente") == "urgente"


# ---------- mensagens inocentes (não podem gerar sinal) ----------
def test_mensagem_inocente_nao_gera_sinais():
    assert codigos("Oi, tudo bem? Vamos almoçar amanhã?") == set()


def test_fatura_normal_nao_gera_sinais():
    assert codigos("Sua fatura de outubro já está disponível no app.") == set()


def test_pedido_entregue_nao_gera_sinais():
    assert codigos("Seu pedido foi entregue hoje. Obrigado por comprar!") == set()


# ---------- golpes reais ----------
def test_golpe_falsa_operadora():
    texto = (
        "CLARO: sua fatura está em atraso e sua linha será bloqueada hoje! "
        "Pague via PIX imediatamente: http://claro-fatura.xyz"
    )
    achados = codigos(texto)
    assert {
        "cobranca_pendente",
        "ameaca_bloqueio",
        "pedido_pix",
        "urgencia_falsa",
    } <= achados


def test_golpe_falso_parente():
    achados = codigos("Oi mãe, mudei de número. Perdi meu celular, salva esse novo número.")
    assert "falso_parente" in achados


def test_golpe_falso_parente_com_pedido_de_pix():
    achados = codigos("Oi pai, perdi meu celular. Preciso que faça um pix pra mim")
    assert {"falso_parente", "pedido_pix"} <= achados


def test_pedido_de_codigo_e_sinal_forte():
    sinais = analisar_regras("Informe o código que enviamos por SMS para confirmar")
    s = next(x for x in sinais if x.codigo == "pedido_dados_sensiveis")
    assert s.forte is True


def test_acesso_remoto_e_sinal_forte():
    sinais = analisar_regras("Baixe o aplicativo AnyDesk para resolver seu problema")
    s = next(x for x in sinais if x.codigo == "instalar_app_ou_acesso_remoto")
    assert s.forte is True


def test_pagamento_antecipado():
    achados = codigos("Pague a taxa para liberar seu saque de R$ 5.000")
    assert "pagamento_antecipado" in achados


def test_promessa_de_premio():
    achados = codigos("Parabéns! Você ganhou um prêmio, resgate agora")
    assert "promessa_premio" in achados


# ---------- robustez ----------
def test_maiusculas_e_acentos_nao_atrapalham():
    achados = codigos("URGENTE!!! SUA CONTA SERÁ BLOQUEADA")
    assert {"urgencia_falsa", "ameaca_bloqueio"} <= achados


def test_caractere_invisivel_nao_engana():
    assert "urgencia_falsa" in codigos("urg\u200bente: responda")


def test_cada_regra_gera_no_maximo_um_sinal():
    sinais = analisar_regras("pix pix pix faça um pix agora")
    assert [s.codigo for s in sinais].count("pedido_pix") == 1


# ---------- integridade das regras ----------
def test_codigos_das_regras_sao_unicos():
    assert len({r.codigo for r in REGRAS}) == len(REGRAS)


def test_todos_os_sinais_vem_da_origem_rules():
    sinais = analisar_regras("urgente, pague via pix a taxa para liberar o saque")
    assert sinais
    assert all(s.origem == "rules" for s in sinais)