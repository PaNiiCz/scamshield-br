from backend.analyzers.url_analyzer import analisar_urls, extrair_urls


def codigos(texto: str) -> set[str]:
    return {s.codigo for s in analisar_urls(texto)}


# ---------- extração ----------
def test_extrai_url_com_esquema():
    assert extrair_urls("Acesse http://claro-fatura.xyz agora.") == [
        "http://claro-fatura.xyz"
    ]


def test_extrai_www_e_remove_pontuacao_do_final():
    assert extrair_urls("veja www.exemplo.com.br/pagar, ok") == [
        "www.exemplo.com.br/pagar"
    ]


def test_extrai_dominio_sem_esquema():
    assert extrair_urls("entre em itau-seguro.top hoje") == ["itau-seguro.top"]


def test_ignora_email():
    assert extrair_urls("escreva para joao.silva@gmail.com agora") == []


def test_ignora_numeros_e_valores():
    assert extrair_urls("Pague R$ 5.000,00 até 15.11 hoje") == []


# ---------- sites verdadeiros não são acusados ----------
def test_site_oficial_nao_gera_sinais():
    texto = "https://www.itau.com.br e https://faturas.claro.com.br/segunda-via"
    assert analisar_urls(texto) == []


# ---------- sinais ----------
def test_imitacao_de_marca_com_tld_suspeito():
    achados = codigos("http://claro-fatura.xyz")
    assert {
        "dominio_imitando_marca",
        "tld_suspeito",
        "url_sem_https",
        "palavra_sensivel_no_dominio",
    } <= achados


def test_marca_oficial_no_comeco_do_endereco_nao_engana():
    assert "dominio_imitando_marca" in codigos("https://claro.com.br.seguro-fatura.xyz")


def test_numero_no_lugar_de_letra_nao_engana():
    assert "dominio_imitando_marca" in codigos("https://1tau-seguro.com")


def test_url_encurtada():
    assert codigos("clique em https://bit.ly/abc123") == {"url_encurtada"}


def test_url_com_ip():
    assert "url_com_ip" in codigos("http://192.168.0.1/login")


def test_url_com_arroba_no_endereco():
    assert "url_com_arroba" in codigos("http://itau.com.br@evil-site.top/login")


def test_punycode():
    assert "dominio_punycode" in codigos("http://xn--itu-qma.com")


def test_subdominios_em_excesso():
    achados = codigos("https://app.login.seguro.banco.exemplo.com/entrar")
    assert "subdominios_excessivos" in achados


# ---------- robustez ----------
def test_texto_sem_url_nao_gera_sinais():
    assert analisar_urls("Oi, tudo bem? Vamos almoçar amanhã?") == []


def test_cada_sinal_aparece_uma_vez_mesmo_com_varias_urls():
    sinais = analisar_urls("http://a-fatura.xyz e http://b-fatura.xyz")
    assert [s.codigo for s in sinais].count("tld_suspeito") == 1


def test_todos_os_sinais_vem_da_origem_url_analyzer():
    sinais = analisar_urls("http://claro-fatura.xyz")
    assert sinais
    assert all(s.origem == "url_analyzer" for s in sinais)