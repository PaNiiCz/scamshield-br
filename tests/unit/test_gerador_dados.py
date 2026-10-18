from scripts.gerar_dados_sinteticos import gerar_dataset


def test_dataset_tem_as_duas_classes_e_as_duas_particoes():
    linhas = gerar_dataset(variantes_por_template=5)
    assert {linha["rotulo"] for linha in linhas} == {0, 1}
    assert {linha["particao"] for linha in linhas} == {"treino", "teste"}


def test_mesma_semente_gera_o_mesmo_dataset():
    assert gerar_dataset(5, semente=7) == gerar_dataset(5, semente=7)


def test_sementes_diferentes_geram_datasets_diferentes():
    assert gerar_dataset(5, semente=1) != gerar_dataset(5, semente=2)


def test_nenhum_modelo_aparece_no_treino_e_no_teste():
    linhas = gerar_dataset(variantes_por_template=5)
    no_treino = {l["grupo"] for l in linhas if l["particao"] == "treino"}
    no_teste = {l["grupo"] for l in linhas if l["particao"] == "teste"}
    assert no_treino.isdisjoint(no_teste)


def test_nao_ha_texto_vazio_nem_campo_sem_preencher():
    for linha in gerar_dataset(variantes_por_template=5):
        assert linha["texto"].strip()
        assert "{" not in linha["texto"]
        assert "}" not in linha["texto"]