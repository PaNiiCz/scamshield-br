"""Classificador estatístico de texto (TF-IDF + Regressão Logística).

É UMA peça do sistema, não o juiz: ele estima o quanto o texto se parece
com mensagens de golpe que aprendeu a reconhecer, e devolve um sinal de
peso limitado (no máximo 20 pontos). As regras e a análise de links
continuam mandando.

Se o arquivo do modelo não existir (ainda não treinado), o sistema
funciona normalmente, só sem este sinal.

Segurança: o arquivo .joblib é um "pickle" e só deve ser carregado se foi
gerado por você mesmo (scripts/train_model.py). Nunca carregue um modelo
baixado de fonte desconhecida.
"""

import re
from functools import lru_cache
from pathlib import Path

import joblib

from backend.analyzers.rules import normalizar
from backend.core.models import Sinal

ORIGEM = "text_classifier"

# <raiz do projeto>/models/text_classifier.joblib
CAMINHO_MODELO = Path(__file__).resolve().parents[2] / "models" / "text_classifier.joblib"

# Faixas de confiança -> pontos (limitados de propósito: ML é só uma peça)
LIMIAR_ALTO = 0.85
LIMIAR_MEDIO = 0.65
PONTOS_ALTO = 20
PONTOS_MEDIO = 10

_RE_LINK = re.compile(r"(?:https?://|www\.)\S+")
_RE_NUMERO = re.compile(r"\d+(?:[.,]\d+)*")


def preparar_texto(texto: str) -> str:
    """Limpa o texto antes de o modelo ler.

    - normaliza (minúsculas, sem acentos, sem caracteres invisíveis)
    - troca cada link por 'linkurl': quem avalia links é o url_analyzer,
      e assim o modelo não decora endereços falsos dos dados de treino
    - troca cada número (ex: 8.000 ou 89,90) por 'num': o valor exato não importa
    """
    texto = normalizar(texto)
    texto = _RE_LINK.sub(" linkurl ", texto)
    texto = _RE_NUMERO.sub(" num ", texto)
    return texto


@lru_cache(maxsize=4)
def carregar_modelo(caminho: str):
    """Carrega o modelo do disco (uma vez só). Devolve None se não existir."""
    arquivo = Path(caminho)
    if not arquivo.exists():
        return None
    try:
        return joblib.load(arquivo)
    except Exception:
        return None


def probabilidade_golpe(texto: str, caminho: Path = CAMINHO_MODELO) -> float | None:
    """Probabilidade (0 a 1) de o texto parecer golpe. None se não há modelo."""
    modelo = carregar_modelo(str(caminho))
    if modelo is None:
        return None
    indice_golpe = list(modelo.classes_).index(1)
    return float(modelo.predict_proba([texto])[0][indice_golpe])


def analisar_ml(texto: str, caminho: Path = CAMINHO_MODELO) -> list[Sinal]:
    """Gera o sinal do modelo estatístico, se houver motivo."""
    probabilidade = probabilidade_golpe(texto, caminho)
    if probabilidade is None:
        return []

    if probabilidade >= LIMIAR_ALTO:
        pontos = PONTOS_ALTO
    elif probabilidade >= LIMIAR_MEDIO:
        pontos = PONTOS_MEDIO
    else:
        return []

    return [
        Sinal(
            codigo="ml_texto_suspeito",
            descricao=(
                "O modelo estatístico achou este texto parecido com mensagens "
                f"de golpe que aprendeu a reconhecer (semelhança estimada: "
                f"{probabilidade:.0%}). É uma estimativa, não uma certeza."
            ),
            pontos=pontos,
            origem=ORIGEM,
            forte=False,
        )
    ]