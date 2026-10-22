"""Testes do analisador de letras falsas / homóglifos (Etapa 8.5).

Letras de outros alfabetos que parecem letras latinas: o "a" latino tem
código 97; o "а" cirílico, que parece igual, tem código 1072.
"""

import time

import pytest

from backend.analyzers.homoglyph_analyzer import (
    MAPA_CONFUSIVEIS,
    analisar_homoglifos,
    desfazer_confusiveis,
)

A_CIR = "\u0430"  # 'а' cirílico (1072), parece 'a' latino (97)
C_CIR = "\u0441"  # 'с' cirílico, parece 'c'
E_CIR = "\u0435"  # 'е' cirílico, parece 'e'
I_CIR = "\u0456"  # 'і' cirílico, parece 'i'
O_CIR = "\u043e"  # 'о' cirílico, parece 'o'
P_CIR = "\u0440"  # 'р' cirílico, parece 'p'
X_CIR = "\u0445"  # 'х' cirílico, parece 'x'

DOMINIO = "dominio_com_letras_falsas"
TEXTO = "letras_trocadas_no_texto"


def _codigos(sinais):
    return [s.codigo for s in sinais]


# --- Mapa e desfazer_confusiveis ---------------------------------------------


def test_os_codigos_do_exemplo_do_usuario():
    assert ord("a") == 97
    assert ord(A_CIR) == 1072
    assert A_CIR != "a"
    assert MAPA_CONFUSIVEIS[A_CIR] == "a"


def test_mapa_so_tem_letras_nao_ascii_que_viram_uma_letra_ascii():
    for falsa, verdadeira in MAPA_CONFUSIVEIS.items():
        assert not falsa.isascii()
        assert len(verdadeira) == 1 and verdadeira.isascii() and verdadeira.isalpha()


@pytest.mark.parametrize(
    "entrada, esperado",
    [
        (f"{P_CIR}ix", "pix"),
        (f"cl{A_CIR}ro", "claro"),
        (f"{C_CIR}{A_CIR}{I_CIR}{X_CIR}{A_CIR}", "caixa"),
        ("\u0421L\u0410R\u041e", "CLARO"),  # maiúsculas cirílicas
        ("g\u03bf\u03bfgle", "google"),  # 'ο' grego
        ("\u0261oogle", "google"),  # 'ɡ' latino especial
    ],
)
def test_desfazer_troca_letras_falsas_pelas_latinas(entrada, esperado):
    assert desfazer_confusiveis(entrada) == esperado


def test_texto_ascii_fica_exatamente_igual():
    texto = "Pague via PIX: http://claro-fatura.xyz agora!"
    assert desfazer_confusiveis(texto) == texto


def test_portugues_com_acentos_nao_e_alterado():
    texto = "Atenção: você não pode perder, é só clicar. Avó, ação, café, pão, coração."
    assert desfazer_confusiveis(texto) == texto


def test_desfazer_e_idempotente_e_aceita_vazio():
    texto = f"{P_CIR}ix cl{A_CIR}ro"
    assert desfazer_confusiveis(desfazer_confusiveis(texto)) == desfazer_confusiveis(texto)
    assert desfazer_confusiveis("") == ""


# --- Endereços falsos ---------------------------------------------------------


def test_endereco_oficial_com_uma_letra_falsa_e_detectado():
    # Antes da Etapa 8.5 isto dava 0 sinais: o link parecia exatamente o oficial.
    sinais = analisar_homoglifos(f"Veja https://www.cl{A_CIR}ro.com.br/fatura")
    assert _codigos(sinais) == [DOMINIO]
    sinal = sinais[0]
    assert sinal.pontos == 40
    assert sinal.forte is True
    assert sinal.origem == "homoglyph_analyzer"


def test_descricao_mostra_os_codigos_e_o_endereco_real():
    descricao = analisar_homoglifos(f"https://www.cl{A_CIR}ro.com.br")[0].descricao
    assert "1072" in descricao
    assert "97" in descricao
    assert "cirílico" in descricao
    assert "xn--" in descricao  # forma real do endereço na rede
    assert "Claro" in descricao


def test_endereco_todo_cirilico_que_imita_marca_e_detectado():
    # "саіха" (c-a-i-x-a, todas cirílicas) vira "caixa", que é a marca Caixa
    sinais = analisar_homoglifos(f"Acesse https://www.{C_CIR}{A_CIR}{I_CIR}{X_CIR}{A_CIR}.gov.br")
    assert _codigos(sinais) == [DOMINIO]
    assert "Caixa" in sinais[0].descricao


def test_mistura_de_alfabetos_na_mesma_palavra_do_endereco_basta():
    sinais = analisar_homoglifos(f"http://l{O_CIR}ja-barata.xyz")
    assert _codigos(sinais) == [DOMINIO]


def test_imitacao_de_marca_com_letra_falsa_e_detectada():
    sinais = analisar_homoglifos(f"Pague em http://cl{A_CIR}ro-fatura.xyz")
    assert _codigos(sinais) == [DOMINIO]


def test_endereco_solto_sem_http_e_detectado():
    sinais = analisar_homoglifos(f"acesse cl{A_CIR}ro.com.br/fatura")
    assert _codigos(sinais) == [DOMINIO]


def test_endereco_de_email_com_letra_falsa_e_detectado():
    sinais = analisar_homoglifos(f"fale com suporte@cl{A_CIR}ro.com.br")
    assert _codigos(sinais) == [DOMINIO]


def test_endereco_cirilico_legitimo_nao_e_acusado():
    # "яндекс.рф": letras em cirílico de verdade, sem imitar marca nenhuma
    sinais = analisar_homoglifos("Visite https://\u044f\u043d\u0434\u0435\u043a\u0441.\u0440\u0444")
    assert sinais == []


def test_endereco_latino_normal_nao_gera_sinal():
    assert analisar_homoglifos("Veja https://www.claro.com.br/fatura e http://minha-loja.com.br") == []


def test_endereco_punycode_nao_e_responsabilidade_deste_analisador():
    assert analisar_homoglifos("http://xn--clro-9ve.com.br") == []


def test_varios_enderecos_falsos_geram_um_unico_sinal():
    texto = f"http://cl{A_CIR}ro.com.br http://v{I_CIR}vo.com.br http://t{I_CIR}m.com.br"
    assert _codigos(analisar_homoglifos(texto)).count(DOMINIO) == 1


# --- Texto --------------------------------------------------------------------


def test_palavra_com_letra_falsa_gera_sinal_de_texto():
    sinais = analisar_homoglifos(f"Pague via {P_CIR}ix agora")
    assert _codigos(sinais) == [TEXTO]
    sinal = sinais[0]
    assert sinal.pontos == 20
    assert sinal.forte is False
    assert sinal.origem == "homoglyph_analyzer"
    assert str(ord(P_CIR)) in sinal.descricao
    assert "ix agora" not in sinal.descricao  # nunca copia trechos da mensagem


def test_texto_em_russo_legitimo_nao_gera_sinal():
    assert analisar_homoglifos("\u041f\u0440\u0438\u0432\u0435\u0442, \u043a\u0430\u043a \u0434\u0435\u043b\u0430?") == []


def test_portugues_normal_nao_gera_sinal():
    assert analisar_homoglifos("Oi, tudo bem? Atenção: ação, você, café, avó.") == []


def test_palavras_em_alfabetos_diferentes_lado_a_lado_nao_geram_sinal():
    assert analisar_homoglifos("\u041f\u0440\u0438\u0432\u0435\u0442 hello") == []


def test_endereco_falso_nao_gera_tambem_o_sinal_de_texto():
    sinais = analisar_homoglifos(f"Veja https://www.cl{A_CIR}ro.com.br/fatura")
    assert TEXTO not in _codigos(sinais)


def test_endereco_falso_e_palavra_falsa_juntos_geram_os_dois_sinais():
    sinais = analisar_homoglifos(f"Pague via {P_CIR}ix em http://cl{A_CIR}ro-fatura.xyz")
    assert sorted(_codigos(sinais)) == sorted([DOMINIO, TEXTO])


def test_descricao_lista_no_maximo_3_letras_diferentes():
    texto = f"{A_CIR}{C_CIR}{E_CIR}{O_CIR}{P_CIR}x"
    descricao = analisar_homoglifos(texto)[0].descricao
    assert descricao.count("código") <= 6  # 3 letras falsas x (falsa + verdadeira)


def test_texto_vazio_devolve_lista_vazia():
    assert analisar_homoglifos("") == []


def test_entrada_gigante_nao_trava():
    texto = (f"cl{A_CIR}ro " + "a" * 50 + " " + f"{P_CIR}ix.") * 150
    inicio = time.perf_counter()
    analisar_homoglifos(texto[:10_000])
    assert time.perf_counter() - inicio < 1.0