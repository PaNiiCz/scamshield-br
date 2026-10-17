from backend.core.models import NivelRisco, Sinal
from backend.risk.risk_engine import calcular_risco


def sinal(codigo: str, pontos: int, forte: bool = False) -> Sinal:
    return Sinal(
        codigo=codigo,
        descricao="teste",
        pontos=pontos,
        origem="teste",
        forte=forte,
    )


def test_sem_sinais_e_verde_zero():
    v = calcular_risco([])
    assert v.pontuacao == 0
    assert v.nivel == NivelRisco.VERDE


def test_pontuacao_baixa_e_verde():
    v = calcular_risco([sinal("urgencia_falsa", 15)])
    assert v.pontuacao == 15
    assert v.nivel == NivelRisco.VERDE
    assert v.motivo_forcado is None


def test_pontuacao_media_e_laranja():
    v = calcular_risco([sinal("urgencia_falsa", 15), sinal("ameaca_bloqueio", 20)])
    assert v.pontuacao == 35
    assert v.nivel == NivelRisco.LARANJA


def test_pontuacao_alta_e_vermelho():
    v = calcular_risco(
        [sinal("pedido_pix", 20), sinal("ameaca_bloqueio", 20), sinal("x", 30)]
    )
    assert v.pontuacao == 70
    assert v.nivel == NivelRisco.VERMELHO


def test_pontuacao_nunca_passa_de_100():
    v = calcular_risco([sinal(f"s{i}", 30) for i in range(10)])
    assert v.pontuacao == 100


def test_limites_exatos_dos_niveis():
    assert calcular_risco([sinal("a", 29)]).nivel == NivelRisco.VERDE
    assert calcular_risco([sinal("a", 30)]).nivel == NivelRisco.LARANJA
    assert calcular_risco([sinal("a", 59)]).nivel == NivelRisco.LARANJA
    assert calcular_risco([sinal("a", 60)]).nivel == NivelRisco.VERMELHO


def test_sinal_forte_forca_laranja_e_ajusta_pontuacao():
    v = calcular_risco([sinal("instalar_app_ou_acesso_remoto", 25, forte=True)])
    assert v.nivel == NivelRisco.LARANJA
    assert v.pontuacao == 30  # sobe até o piso do laranja
    assert v.motivo_forcado is not None


def test_combinacao_forca_laranja_mesmo_com_pontos_baixos():
    v = calcular_risco(
        [
            sinal("pedido_pix", 5),
            sinal("urgencia_falsa", 5),
            sinal("dominio_imitando_marca", 5),
        ]
    )
    assert v.nivel == NivelRisco.LARANJA
    assert v.motivo_forcado is not None


def test_regra_de_seguranca_nunca_rebaixa_vermelho():
    v = calcular_risco([sinal("a", 70, forte=True)])
    assert v.nivel == NivelRisco.VERMELHO
    assert v.pontuacao == 70
    assert v.motivo_forcado is None