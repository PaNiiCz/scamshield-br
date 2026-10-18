"""Treina o classificador de texto e salva em models/text_classifier.joblib.

Uso (na raiz do projeto, depois de gerar os dados):
    python -m scripts.train_model

Passo 1: mede a qualidade treinando SEM os modelos de mensagem reservados
         para teste (formatos que o classificador nunca viu).
Passo 2: treina o modelo final com TODOS os dados e salva.
Também imprime as palavras que mais pesam em cada direção (explicabilidade).
"""

import csv
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline

from backend.analyzers.text_classifier import CAMINHO_MODELO, preparar_texto
from scripts.gerar_dados_sinteticos import CAMINHO_CSV

CAMINHO_METRICAS = CAMINHO_MODELO.parent / "text_classifier_metrics.json"


def carregar_dados(caminho: Path = CAMINHO_CSV):
    treino_x, treino_y, teste_x, teste_y = [], [], [], []
    with caminho.open(encoding="utf-8", newline="") as arquivo:
        for linha in csv.DictReader(arquivo):
            if linha["particao"] == "treino":
                treino_x.append(linha["texto"])
                treino_y.append(int(linha["rotulo"]))
            else:
                teste_x.append(linha["texto"])
                teste_y.append(int(linha["rotulo"]))
    return treino_x, treino_y, teste_x, teste_y


def construir_pipeline() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    preprocessor=preparar_texto,
                    ngram_range=(1, 2),
                    min_df=2,
                    sublinear_tf=True,
                ),
            ),
            ("regressao", LogisticRegression(max_iter=1000, class_weight="balanced")),
        ]
    )


def imprimir_palavras_mais_pesadas(pipeline: Pipeline, quantas: int = 12) -> None:
    palavras = pipeline.named_steps["tfidf"].get_feature_names_out()
    pesos = pipeline.named_steps["regressao"].coef_[0]
    ordenadas = sorted(zip(pesos, palavras))
    print("\nPalavras que mais empurram para LEGÍTIMA:")
    for peso, palavra in ordenadas[:quantas]:
        print(f"  {palavra:<25} {peso:+.2f}")
    print("\nPalavras que mais empurram para GOLPE:")
    for peso, palavra in reversed(ordenadas[-quantas:]):
        print(f"  {palavra:<25} {peso:+.2f}")


def main() -> None:
    if not CAMINHO_CSV.exists():
        raise SystemExit(
            "Dataset não encontrado. Rode antes: python -m scripts.gerar_dados_sinteticos"
        )

    treino_x, treino_y, teste_x, teste_y = carregar_dados()
    print(f"Treino: {len(treino_x)} mensagens | Teste: {len(teste_x)} mensagens")

    pipeline = construir_pipeline()
    pipeline.fit(treino_x, treino_y)

    previsoes = pipeline.predict(teste_x)
    relatorio = classification_report(
        teste_y, previsoes, target_names=["legitima", "golpe"], digits=3, output_dict=True
    )
    print("\n" + classification_report(
        teste_y, previsoes, target_names=["legitima", "golpe"], digits=3
    ))

    matriz = confusion_matrix(teste_y, previsoes)
    print("Matriz de confusão (linhas = real, colunas = previsto):")
    print("                 prev.legitima  prev.golpe")
    print(f"  real legitima  {matriz[0][0]:>12}  {matriz[0][1]:>10}")
    print(f"  real golpe     {matriz[1][0]:>12}  {matriz[1][1]:>10}")
    print(
        "\n(Falso negativo = golpe que passou como legítimo. "
        f"Neste teste: {matriz[1][0]})"
    )

    # Modelo FINAL: depois de medir a qualidade (acima), treinamos de novo com
    # TODAS as mensagens, inclusive os modelos reservados para o teste. É a
    # prática padrão: o teste serve para medir, o modelo final aprende tudo.
    modelo_final = construir_pipeline()
    modelo_final.fit(treino_x + teste_x, treino_y + teste_y)

    imprimir_palavras_mais_pesadas(modelo_final)

    CAMINHO_MODELO.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(modelo_final, CAMINHO_MODELO)
    CAMINHO_METRICAS.write_text(
        json.dumps(
            {
                "aviso": "Métricas em dados SINTÉTICOS (otimistas). Avaliação real: Fase 2.",
                "mensagens_treino": len(treino_x),
                "mensagens_teste": len(teste_x),
                "observacao": "metricas medidas sem os modelos de teste; o modelo salvo usa todos os dados",
                "golpe": relatorio["golpe"],
                "legitima": relatorio["legitima"],
                "acuracia": relatorio["accuracy"],
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"\nModelo salvo em: {CAMINHO_MODELO}")
    print(f"Métricas salvas em: {CAMINHO_METRICAS}")


if __name__ == "__main__":
    main()