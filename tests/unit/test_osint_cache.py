"""Testes do cache com validade do OSINT (Etapa 8)."""

from backend.osint.cache import CacheTTL


class Relogio:
    def __init__(self):
        self.agora = 1000.0

    def __call__(self):
        return self.agora


def test_guarda_e_devolve_valor():
    cache = CacheTTL(validade_segundos=60, relogio=Relogio())
    cache.guardar("a", 123)
    achou, valor = cache.buscar("a")
    assert achou is True
    assert valor == 123


def test_chave_inexistente_nao_acha():
    cache = CacheTTL(validade_segundos=60, relogio=Relogio())
    assert cache.buscar("nada") == (False, None)


def test_valor_none_tambem_e_guardado():
    # "não sei / não existe" também vale a pena lembrar, para não repetir a consulta
    cache = CacheTTL(validade_segundos=60, relogio=Relogio())
    cache.guardar("a", None)
    assert cache.buscar("a") == (True, None)


def test_valor_expira_depois_da_validade():
    relogio = Relogio()
    cache = CacheTTL(validade_segundos=60, relogio=relogio)
    cache.guardar("a", 1)
    relogio.agora += 61
    assert cache.buscar("a") == (False, None)


def test_valor_ainda_vale_antes_da_validade():
    relogio = Relogio()
    cache = CacheTTL(validade_segundos=60, relogio=relogio)
    cache.guardar("a", 1)
    relogio.agora += 59
    assert cache.buscar("a") == (True, 1)


def test_tamanho_maximo_descarta_o_mais_antigo():
    cache = CacheTTL(validade_segundos=60, tamanho_maximo=2, relogio=Relogio())
    cache.guardar("a", 1)
    cache.guardar("b", 2)
    cache.guardar("c", 3)
    assert cache.buscar("a") == (False, None)
    assert cache.buscar("b") == (True, 2)
    assert cache.buscar("c") == (True, 3)


def test_limpar_esvazia_tudo():
    cache = CacheTTL(validade_segundos=60, relogio=Relogio())
    cache.guardar("a", 1)
    cache.limpar()
    assert cache.buscar("a") == (False, None)