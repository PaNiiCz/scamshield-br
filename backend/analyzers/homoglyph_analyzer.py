"""Letras falsas (homóglifos): letras de outros alfabetos que imitam letras latinas.

O "a" latino tem o código 97. O "а" cirílico, que na tela parece IDÊNTICO,
tem o código 1072. Para o computador são letras diferentes; para quem lê,
não. Golpistas usam isso em dois lugares:

- no ENDEREÇO: "clаro.com.br" (com "а" cirílico) parece o site da Claro,
  mas é outro endereço, registrado pelo golpista;
- no TEXTO: "рix" (com "р" cirílico) escapa de filtros que procuram "pix".

Este módulo faz duas coisas:
1. desfazer_confusiveis(): troca cada letra falsa pela latina parecida, para
   as regras, o modelo e o analisador de URLs "enxergarem" o que o olho vê.
2. analisar_homoglifos(): avisa o usuário de que o truque existe.

Totalmente passivo: só olha o texto, nunca acessa nada.
"""

import re
import unicodedata
from urllib.parse import urlparse

from backend.analyzers.url_analyzer import (
    dominio_registrado,
    e_oficial,
    extrair_urls,
    marca_imitada,
)
from backend.core.models import Sinal

ORIGEM = "homoglyph_analyzer"

# letra falsa -> letra latina que ela imita (conjunto conservador: só
# letras que, na tela, quase não se distinguem da latina)
MAPA_CONFUSIVEIS: dict[str, str] = {
    # cirílico minúsculo
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0501": "d", "\u051b": "q", "\u051d": "w", "\u04bb": "h", "\u04cf": "l",
    "\u043a": "k",
    # cirílico maiúsculo
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0423": "Y", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    "\u051a": "Q", "\u051c": "W", "\u04c0": "l",
    # grego minúsculo
    "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03c1": "p", "\u03b9": "i",
    "\u03ba": "k", "\u03c5": "u", "\u03c7": "x",
    # grego maiúsculo
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # latinas "especiais" (do alfabeto fonético)
    "\u0261": "g", "\u0131": "i", "\u0251": "a",
}

_TABELA = str.maketrans(MAPA_CONFUSIVEIS)

_NOMES_ALFABETO = {"CYRILLIC": "cirílico", "GREEK": "grego", "LATIN": "latino especial"}

# pedaço parecido com endereço: palavras ligadas por pontos (letras de qualquer alfabeto)
_RE_ENDERECO_SOLTO = re.compile(r"[\w-]+(?:\.[\w-]+)+")
_RE_PALAVRA = re.compile(r"[^\W\d_]+")


def desfazer_confusiveis(texto: str) -> str:
    """Troca cada letra falsa pela letra latina que ela imita.

    Texto só com ASCII volta idêntico (nada muda para mensagens normais).
    """
    if texto.isascii():
        return texto
    return unicodedata.normalize("NFKC", texto).translate(_TABELA)


def _letras_falsas(texto: str) -> list[str]:
    return [c for c in texto if c in MAPA_CONFUSIVEIS]


def _tem_letra_ascii(texto: str) -> bool:
    return any(c.isascii() and c.isalpha() for c in texto)


def _descrever_letras(caracteres: list[str]) -> str:
    """Até 3 letras falsas diferentes, com o código de cada uma e o da letra imitada."""
    vistas: list[str] = []
    for c in caracteres:
        if c not in vistas:
            vistas.append(c)
        if len(vistas) == 3:
            break
    partes = []
    for c in vistas:
        alfabeto = _NOMES_ALFABETO.get(unicodedata.name(c, "").split(" ")[0], "outro alfabeto")
        latina = MAPA_CONFUSIVEIS[c]
        partes.append(
            f"'{c}' ({alfabeto}, código {ord(c)}) no lugar de '{latina}' (latino, código {ord(latina)})"
        )
    return "; ".join(partes)


def _host_da_url(url: str) -> str | None:
    try:
        host = urlparse(url if "://" in url else "http://" + url).hostname
    except ValueError:
        return None
    return host.rstrip(".") if host else None


def _forma_real(host: str) -> str | None:
    """Como o endereço é registrado na rede (xn--...), ou None se não der para converter."""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _avaliar_endereco(host: str) -> Sinal | None:
    """Sinal se o endereço usa letras falsas para imitar um endereço conhecido ou comum."""
    falsas = _letras_falsas(host)
    if not falsas:
        return None

    desfeito = desfazer_confusiveis(host)
    if "." not in dominio_registrado(desfeito):
        return None  # não parece endereço de verdade (sem sufixo como .com ou .br)

    mistura = any(
        _letras_falsas(rotulo) and _tem_letra_ascii(rotulo) for rotulo in host.split(".")
    )
    marca = marca_imitada(desfeito)
    if not (mistura or marca or e_oficial(desfeito)):
        return None  # cirílico legítimo (ex.: um site russo): não acusamos

    alvo = f"o site da {marca.nome}" if marca else "um endereço comum"
    real = _forma_real(host)
    complemento = f" Na rede, ele é registrado como '{real}', um endereço diferente do que parece." if real else ""
    return Sinal(
        codigo="dominio_com_letras_falsas",
        descricao=(
            f"O endereço '{host}' usa letras de outros alfabetos que parecem letras latinas "
            f"({_descrever_letras(falsas)}).{complemento} É um truque para imitar {alvo}."
        ),
        pontos=40,
        origem=ORIGEM,
        forte=True,
    )


def analisar_homoglifos(texto: str) -> list[Sinal]:
    """Procura letras falsas em endereços e em palavras da mensagem."""
    if not texto or texto.isascii():
        return []

    sinais: list[Sinal] = []
    consumidos: list[str] = []  # pedaços já avaliados como endereço (não viram "texto")

    candidatos: list[str] = []
    for url in extrair_urls(texto):
        host = _host_da_url(url)
        if host:
            candidatos.append(host)
            consumidos.append(url)
    for achado in _RE_ENDERECO_SOLTO.finditer(texto):
        pedaco = achado.group()
        if _letras_falsas(pedaco):
            host = _host_da_url(pedaco)
            if host:
                candidatos.append(host)
                consumidos.append(pedaco)

    sinal_endereco = None
    for host in dict.fromkeys(candidatos):
        sinal_endereco = _avaliar_endereco(host)
        if sinal_endereco:
            break
    if sinal_endereco:
        sinais.append(sinal_endereco)

    restante = texto
    for pedaco in consumidos:
        restante = restante.replace(pedaco, " ")
    falsas_no_texto: list[str] = []
    for palavra in _RE_PALAVRA.findall(restante):
        falsas = _letras_falsas(palavra)
        if falsas and _tem_letra_ascii(palavra):
            falsas_no_texto.extend(falsas)
    if falsas_no_texto:
        sinais.append(
            Sinal(
                codigo="letras_trocadas_no_texto",
                descricao=(
                    "A mensagem mistura letras de outros alfabetos com letras latinas dentro da "
                    f"mesma palavra ({_descrever_letras(falsas_no_texto)}). É um truque para "
                    "escapar de filtros e parecer um texto normal."
                ),
                pontos=20,
                origem=ORIGEM,
                forte=False,
            )
        )
    return sinais