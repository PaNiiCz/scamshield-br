import pytest

from backend.security.pii_masking import mascarar_com_contagem, mascarar_pii


def test_mascara_cpf_formatado():
    r = mascarar_pii("Meu CPF é 123.456.789-09, ok?")
    assert "123.456.789-09" not in r
    assert "[CPF]" in r


def test_mascara_cnpj():
    r = mascarar_pii("Empresa 12.345.678/0001-95 cobrando")
    assert "12.345.678/0001-95" not in r
    assert "[CNPJ]" in r


def test_mascara_email():
    r = mascarar_pii("Escreva para joao.silva@gmail.com agora")
    assert "joao.silva@gmail.com" not in r
    assert "[EMAIL]" in r


def test_mascara_cartao():
    r = mascarar_pii("Cartão 4111 1111 1111 1111 vence hoje")
    assert "4111" not in r
    assert "[CARTAO]" in r


def test_mascara_chave_pix_aleatoria():
    r = mascarar_pii("Chave: 123e4567-e89b-12d3-a456-426614174000")
    assert "123e4567" not in r
    assert "[CHAVE_PIX]" in r


@pytest.mark.parametrize(
    "telefone",
    [
        "(21) 99999-8888",
        "21999998888",
        "+55 21 99999-8888",
        "21 3333-4444",
        "99999-8888",
    ],
)
def test_mascara_formatos_de_telefone(telefone):
    r = mascarar_pii(f"Me chama no {telefone} agora")
    assert "[TELEFONE]" in r
    assert "9999" not in r
    assert "3333" not in r


def test_texto_sem_pii_fica_igual():
    texto = "Seu pacote chegou. Pague R$ 1500,00 até 15/11 para liberar."
    assert mascarar_pii(texto) == texto


def test_mascarar_duas_vezes_da_o_mesmo_resultado():
    texto = "CPF 123.456.789-09 e tel (21) 99999-8888"
    uma_vez = mascarar_pii(texto)
    assert mascarar_pii(uma_vez) == uma_vez


def test_mensagem_completa_nao_vaza_nada():
    texto = (
        "Olá, sou da Claro. Seu CPF 123.456.789-09 está pendente. "
        "Ligue (21) 99999-8888 ou escreva para atendimento@claro-falso.com. "
        "Pague no cartão 4111 1111 1111 1111."
    )
    r = mascarar_com_contagem(texto)
    for original in [
        "123.456.789-09",
        "99999-8888",
        "atendimento@claro-falso.com",
        "4111",
    ]:
        assert original not in r.texto
    assert r.contagem == {"email": 1, "cartao": 1, "cpf": 1, "telefone": 1}
    assert r.total == 4

def test_cpf_sem_pontuacao_valido_vira_cpf():
    # 12345678909 tem os dígitos verificadores corretos
    r = mascarar_pii("CPF 12345678909 pendente")
    assert "12345678909" not in r
    assert "[CPF]" in r


def test_onze_digitos_que_parecem_telefone_viram_telefone():
    r = mascarar_pii("Fale no 21999998888")
    assert "[TELEFONE]" in r
    assert "[CPF]" not in r


def test_onze_digitos_estranhos_nao_vazam():
    # Não é CPF válido nem tem formato de telefone: cai na rede de segurança
    r = mascarar_pii("Número 12345678900 informado")
    assert "12345678900" not in r
    assert "[DOCUMENTO]" in r


def test_cpf_com_hifen_e_sem_pontos_do_meio():
    r = mascarar_pii("CPF 123456789-09")
    assert "123456789-09" not in r
    assert "[CPF]" in r