"""Testes do analisador de cabeçalhos de e-mail (Etapa 7)."""

from backend.analyzers.email_header_analyzer import analisar_cabecalhos


def _codigos(sinais):
    return {s.codigo for s in sinais}


def _pontos(sinais):
    return {s.codigo: s.pontos for s in sinais}


CABECALHO_LEGITIMO = (
    "Authentication-Results: mx.google.com;\n"
    "       dkim=pass header.i=@claro.com.br;\n"
    "       spf=pass smtp.mailfrom=faturas@claro.com.br;\n"
    "       dmarc=pass (p=REJECT) header.from=claro.com.br\n"
    "Return-Path: <faturas@claro.com.br>\n"
    "From: Claro <faturas@claro.com.br>\n"
    "To: voce@gmail.com\n"
    "Subject: Sua fatura\n"
)

CABECALHO_FALSO = (
    "Authentication-Results: mx.google.com;\n"
    "       dkim=fail header.i=@claro-fatura.xyz;\n"
    "       spf=fail smtp.mailfrom=suporte@claro-fatura.xyz;\n"
    "       dmarc=fail header.from=claro-fatura.xyz\n"
    "Return-Path: <bounce@servidor-obscuro.top>\n"
    "From: Claro Atendimento <suporte@claro-fatura.xyz>\n"
    "Reply-To: golpista@gmail.com\n"
    "To: voce@gmail.com\n"
    "Subject: Fatura em atraso\n"
)


# --- cabeçalhos legítimos --------------------------------------------------


def test_cabecalho_legitimo_nao_gera_sinais():
    assert analisar_cabecalhos(CABECALHO_LEGITIMO) == []


# --- cabeçalhos falsos -----------------------------------------------------


def test_cabecalho_falso_dispara_os_sinais_esperados():
    codigos = _codigos(analisar_cabecalhos(CABECALHO_FALSO))
    assert codigos == {
        "remetente_spf_falhou",
        "dkim_falhou",
        "dmarc_falhou",
        "reply_to_diferente",
        "return_path_diferente",
        "nome_exibicao_imitando_marca",
        "dominio_remetente_imitando_marca",
        "dominio_remetente_suspeito",
    }


def test_cabecalho_falso_tem_pontos_exatos_e_sem_duplicar():
    sinais = analisar_cabecalhos(CABECALHO_FALSO)
    assert len(sinais) == 8  # cada sinal aparece uma única vez
    assert _pontos(sinais) == {
        "remetente_spf_falhou": 25,
        "dkim_falhou": 20,
        "dmarc_falhou": 20,
        "reply_to_diferente": 20,
        "return_path_diferente": 10,
        "nome_exibicao_imitando_marca": 30,
        "dominio_remetente_imitando_marca": 30,
        "dominio_remetente_suspeito": 10,
    }


def test_todos_os_sinais_tem_origem_email_header_analyzer():
    for sinal in analisar_cabecalhos(CABECALHO_FALSO):
        assert sinal.origem == "email_header_analyzer"


# --- SPF -------------------------------------------------------------------


def test_spf_softfail_vale_15():
    cab = (
        "Authentication-Results: mx.exemplo.com; spf=softfail smtp.mailfrom=a@loja.com.br\n"
        "From: Loja <a@loja.com.br>\n"
    )
    assert _pontos(analisar_cabecalhos(cab)) == {"remetente_spf_falhou": 15}


def test_spf_vem_do_received_spf_quando_nao_ha_authentication_results():
    cab = (
        "Received-SPF: fail (dominio nao autoriza o IP) client-ip=1.2.3.4\n"
        "From: Loja <a@loja.com.br>\n"
    )
    assert _pontos(analisar_cabecalhos(cab)) == {"remetente_spf_falhou": 25}


def test_usa_so_o_authentication_results_mais_de_cima():
    # O de baixo (spf=fail) pode ter sido inserido pelo remetente.
    cab = (
        "Authentication-Results: mx.destino.com; spf=pass smtp.mailfrom=a@loja.com.br\n"
        "Authentication-Results: mx.falso.com; spf=fail smtp.mailfrom=a@loja.com.br\n"
        "From: Loja <a@loja.com.br>\n"
    )
    assert analisar_cabecalhos(cab) == []


def test_dkim_ausente_nao_e_falha():
    cab = (
        "Authentication-Results: mx.exemplo.com; dkim=none; spf=pass\n"
        "From: Loja <a@loja.com.br>\n"
    )
    assert analisar_cabecalhos(cab) == []


def test_dkim_com_duas_assinaturas_uma_valida_nao_e_falha():
    cab = (
        "Authentication-Results: mx.exemplo.com;\n"
        " dkim=pass header.d=loja.com.br;\n"
        " dkim=fail header.d=lista-de-emails.com\n"
        "From: Loja <a@loja.com.br>\n"
    )
    assert analisar_cabecalhos(cab) == []


# --- Reply-To e Return-Path ------------------------------------------------


def test_reply_to_do_mesmo_dominio_nao_gera_sinal():
    cab = (
        "From: Loja <a@loja.com.br>\n"
        "Reply-To: suporte@mail.loja.com.br\n"
    )
    assert analisar_cabecalhos(cab) == []


def test_reply_to_de_outro_dominio_gera_sinal():
    cab = (
        "From: Loja <a@loja.com.br>\n"
        "Reply-To: outra.pessoa@gmail.com\n"
    )
    assert _pontos(analisar_cabecalhos(cab)) == {"reply_to_diferente": 20}


def test_return_path_de_outro_dominio_gera_sinal():
    cab = (
        "Return-Path: <bounce@outro-servico.com>\n"
        "From: Loja <a@loja.com.br>\n"
    )
    assert _pontos(analisar_cabecalhos(cab)) == {"return_path_diferente": 10}


# --- nome de exibição e domínio do remetente -------------------------------


def test_nome_de_exibicao_com_marca_e_dominio_oficial_nao_gera_sinal():
    cab = "From: Itaú Unibanco <aviso@itau.com.br>\n"
    assert analisar_cabecalhos(cab) == []


def test_nome_de_exibicao_com_marca_e_dominio_comum_gera_sinal():
    cab = "From: Banco Itaú <aviso@gmail.com>\n"
    assert _pontos(analisar_cabecalhos(cab)) == {"nome_exibicao_imitando_marca": 30}


def test_pessoa_chamada_tim_nao_e_acusada_de_imitar_a_operadora():
    cab = "From: Tim Silva <tim.silva@gmail.com>\n"
    assert analisar_cabecalhos(cab) == []


def test_tim_atendimento_em_dominio_comum_gera_sinal():
    cab = "From: TIM Atendimento <contato@gmail.com>\n"
    assert _codigos(analisar_cabecalhos(cab)) == {"nome_exibicao_imitando_marca"}


def test_dominio_remetente_imitando_marca():
    cab = "From: Aviso <aviso@nubank-seguro.com>\n"
    assert _codigos(analisar_cabecalhos(cab)) == {"dominio_remetente_imitando_marca"}


def test_subdominio_do_dominio_oficial_nao_e_acusado():
    cab = "From: Claro <noreply@mail.claro.com.br>\n"
    assert analisar_cabecalhos(cab) == []


def test_dominio_remetente_com_tld_suspeito():
    cab = "From: Promocoes <ola@ofertas-do-dia.top>\n"
    assert _codigos(analisar_cabecalhos(cab)) == {"dominio_remetente_suspeito"}


def test_dominio_remetente_punycode():
    cab = "From: Aviso <a@xn--itaú-9qa.com>\n"
    assert "dominio_remetente_suspeito" in _codigos(analisar_cabecalhos(cab))


# --- entradas ruins não quebram --------------------------------------------


def test_vazio_ou_so_espacos_devolve_lista_vazia():
    assert analisar_cabecalhos("") == []
    assert analisar_cabecalhos("   \n  ") == []


def test_lixo_vira_cabecalhos_invalidos_com_5_pontos():
    sinais = analisar_cabecalhos("isto nao e um cabecalho de email %%%")
    assert _pontos(sinais) == {"cabecalhos_invalidos": 5}


def test_from_quebrado_nao_gera_excecao():
    cab = "From: <<<>>> sem arroba\nReply-To: ???\n"
    sinais = analisar_cabecalhos(cab)  # só não pode lançar exceção
    assert isinstance(sinais, list)


def test_cabecalho_com_quebra_de_linha_windows():
    cab = CABECALHO_FALSO.replace("\n", "\r\n")
    assert len(analisar_cabecalhos(cab)) == 8


def test_descricoes_nao_expoem_o_endereco_completo():
    # Privacidade: só o domínio aparece, nunca a parte antes do "@".
    for sinal in analisar_cabecalhos(CABECALHO_FALSO):
        assert "suporte@" not in sinal.descricao
        assert "golpista@" not in sinal.descricao
        assert "bounce@" not in sinal.descricao