"""Analisador de URLs do ScamShield BR.

Examina a ESTRUTURA dos links encontrados no texto. É uma análise
totalmente passiva: o link NUNCA é acessado, aberto ou resolvido.

Limitação conhecida: a lista de domínios oficiais é pequena e vai
crescendo. Uma marca que opera em vários países (ex: Claro em outros
países) pode gerar falso positivo fora do Brasil.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse

import tldextract

from backend.core.models import Sinal

ORIGEM = "url_analyzer"

# suffix_list_urls=() => usa só a lista de sufixos que vem junto com a
# biblioteca, sem acessar a internet.
_EXTRATOR = tldextract.TLDExtract(suffix_list_urls=())

# ---------------------------------------------------------------------------
# Dados de referência
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Marca:
    nome: str
    palavras: tuple[str, ...]  # como a marca costuma aparecer em endereços falsos
    dominios_oficiais: tuple[str, ...]


MARCAS: tuple[Marca, ...] = (
    Marca("Claro", ("claro",), ("claro.com.br", "claro.com")),
    Marca("Vivo", ("vivo",), ("vivo.com.br",)),
    Marca("TIM", ("tim",), ("tim.com.br",)),
    Marca("Itaú", ("itau",), ("itau.com.br", "itau.com")),
    Marca("Bradesco", ("bradesco",), ("bradesco.com.br", "banco.bradesco")),
    Marca("Santander", ("santander",), ("santander.com.br", "santander.com")),
    Marca("Nubank", ("nubank",), ("nubank.com.br", "nu.com.br")),
    Marca("Caixa", ("caixa",), ("caixa.gov.br",)),
    Marca("Banco do Brasil", ("bancodobrasil",), ("bb.com.br", "bancodobrasil.com.br")),
    Marca(
        "Mercado Livre / Mercado Pago",
        ("mercadolivre", "mercadopago"),
        ("mercadolivre.com.br", "mercadopago.com.br", "mercadolivre.com"),
    ),
    Marca("Correios", ("correios",), ("correios.com.br",)),
    Marca("Serasa", ("serasa",), ("serasa.com.br",)),
    Marca("PicPay", ("picpay",), ("picpay.com",)),
    Marca("Banco Inter", ("bancointer",), ("bancointer.com.br", "inter.co")),
    Marca("Receita Federal", ("receitafederal",), ("gov.br",)),
)

ENCURTADORES = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "is.gd", "rb.gy",
        "goo.gl", "ow.ly", "shorturl.at", "tiny.cc",
    }
)

TLDS_SUSPEITOS = frozenset(
    {
        "xyz", "top", "click", "icu", "buzz", "cfd", "sbs", "vip", "rest",
        "monster", "tk", "ml", "ga", "cf", "gq", "link", "cyou", "quest",
    }
)

PALAVRAS_SENSIVEIS = (
    "login", "segur", "atualiz", "fatura", "boleto", "pagamento",
    "verific", "acesso", "cadastro", "regulariz", "desbloque",
    "recadastr", "token", "protocolo",
)

# Troca de números por letras parecidas (truque comum: "1tau", "cl4ro")
_TROCAS = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "@": "a"})

# ---------------------------------------------------------------------------
# Extração de URLs do texto
# ---------------------------------------------------------------------------

# Links que começam com http://, https:// ou www.
_RE_URL_COM_ESQUEMA = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)

# Domínios soltos, sem http (ex: "itau-seguro.top"). Não aceita e-mails:
# não pode vir logo depois de um "@" nem ser seguido de "@".
_RE_DOMINIO_SOLTO = re.compile(
    r"(?<![\w@.\-])"
    r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
    r"(?:/[^\s<>\"']*)?"
    r"(?![\w@\-])",
    re.IGNORECASE,
)

_PONTUACAO_FINAL = ".,;:!?)]}>\"'"


def _fazer_parse(url: str) -> ParseResult | None:
    alvo = url if "://" in url else "http://" + url
    try:
        return urlparse(alvo)
    except ValueError:
        return None


def _tem_sufixo_valido(host: str) -> bool:
    return _EXTRATOR(host).suffix != ""


def extrair_urls(texto: str) -> list[str]:
    """Acha os links do texto (com ou sem http), sem repetir."""
    encontradas: list[str] = []

    for achado in _RE_URL_COM_ESQUEMA.finditer(texto):
        url = achado.group().rstrip(_PONTUACAO_FINAL)
        if url:
            encontradas.append(url)

    # Tira os links já achados antes de procurar domínios soltos.
    restante = _RE_URL_COM_ESQUEMA.sub(" ", texto)
    for achado in _RE_DOMINIO_SOLTO.finditer(restante):
        candidato = achado.group().rstrip(_PONTUACAO_FINAL)
        parse = _fazer_parse(candidato)
        if parse and parse.hostname and _tem_sufixo_valido(parse.hostname):
            encontradas.append(candidato)

    return list(dict.fromkeys(encontradas))  # remove repetidos, mantém a ordem


# ---------------------------------------------------------------------------
# Funções públicas de apoio (usadas também pelo analisador de e-mail)
# ---------------------------------------------------------------------------


def e_oficial(host: str) -> bool:
    """True se o endereço é (ou é subdomínio de) um domínio oficial conhecido."""
    return any(
        host == dominio or host.endswith("." + dominio)
        for marca in MARCAS
        for dominio in marca.dominios_oficiais
    )


def _variantes(host: str) -> set[str]:
    """O endereço como está + versões com números trocados por letras."""
    base = host.translate(_TROCAS)
    return {host, base.replace("1", "l"), base.replace("1", "i")}


def marca_imitada(host: str) -> Marca | None:
    """Marca cujo nome aparece no endereço. Não confere se o host é oficial."""
    for variante in _variantes(host):
        compacto = variante.replace("-", "")
        pedacos = set(re.split(r"[.\-]", variante))
        for marca in MARCAS:
            for palavra in marca.palavras:
                # Palavras longas: procura em qualquer parte do endereço.
                # Palavras curtas (tim, vivo, itau): só como pedaço inteiro,
                # para não acusar "ativo" ou "estimado".
                if (len(palavra) >= 5 and palavra in compacto) or palavra in pedacos:
                    return marca
    return None


def dominio_registrado(host: str) -> str:
    """Parte "registrada" do endereço: mail.loja.com.br -> loja.com.br."""
    extraido = _EXTRATOR(host)
    if extraido.suffix:
        return f"{extraido.domain}.{extraido.suffix}"
    return extraido.domain


def tem_punycode(host: str) -> bool:
    """True se algum pedaço do endereço usa a codificação xn--."""
    return any(rotulo.startswith("xn--") for rotulo in host.split("."))


def tem_tld_suspeito(host: str) -> bool:
    """True se o final do endereço (.xyz, .top...) é muito usado em golpes."""
    sufixo = _EXTRATOR(host).suffix
    return bool(sufixo) and sufixo.rsplit(".", 1)[-1] in TLDS_SUSPEITOS


def _e_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Análise de uma URL
# ---------------------------------------------------------------------------


def analisar_url(url: str) -> list[Sinal]:
    """Examina a estrutura de UMA url. Nunca acessa o endereço."""
    parse = _fazer_parse(url)
    if parse is None or not parse.hostname:
        return []

    host = parse.hostname.lower()
    usa_http_puro = url.lower().startswith("http://")

    # Endereço oficial conhecido: não gera sinal (evita acusar o site verdadeiro).
    # Exceção: o truque do "@", em que o host real é outro.
    if e_oficial(host) and not parse.username:
        return []

    sinais: list[Sinal] = []

    def adicionar(codigo: str, descricao: str, pontos: int) -> None:
        sinais.append(
            Sinal(codigo=codigo, descricao=descricao, pontos=pontos, origem=ORIGEM)
        )

    if usa_http_puro:
        adicionar(
            "url_sem_https",
            f"O link '{host}' usa http, sem criptografia. Sites sérios de "
            "pagamento e login usam https.",
            5,
        )

    if parse.username:
        adicionar(
            "url_com_arroba",
            "O link usa o truque do '@': o que aparece antes dele é "
            "enfeite, o destino real é o que vem depois.",
            15,
        )

    if _e_ip(host):
        adicionar(
            "url_com_ip",
            f"O link aponta para um número de IP ({host}) em vez de um "
            "nome de site. Empresas sérias não usam isso em mensagens.",
            20,
        )
        return sinais  # IP não tem domínio nem marca para analisar

    extraido = _EXTRATOR(host)
    registrado = (
        f"{extraido.domain}.{extraido.suffix}" if extraido.suffix else extraido.domain
    )

    if tem_punycode(host):
        adicionar(
            "dominio_punycode",
            f"O endereço '{host}' usa codificação especial (xn--), "
            "técnica usada para imitar sites com letras parecidas.",
            20,
        )

    if registrado in ENCURTADORES:
        adicionar(
            "url_encurtada",
            f"O link usa um encurtador ({registrado}), que esconde o "
            "destino real.",
            10,
        )

    ultimo_rotulo = extraido.suffix.rsplit(".", 1)[-1] if extraido.suffix else ""
    if ultimo_rotulo in TLDS_SUSPEITOS:
        adicionar(
            "tld_suspeito",
            f"O final do endereço (.{ultimo_rotulo}) é muito usado em golpes.",
            10,
        )

    if extraido.subdomain and len(extraido.subdomain.split(".")) >= 3:
        adicionar(
            "subdominios_excessivos",
            f"O endereço '{host}' tem muitas camadas, tática para "
            "esconder o domínio verdadeiro.",
            10,
        )

    if any(palavra in host for palavra in PALAVRAS_SENSIVEIS):
        adicionar(
            "palavra_sensivel_no_dominio",
            f"O endereço '{host}' contém palavras como 'fatura', 'login' "
            "ou 'segurança', típicas de sites falsos.",
            10,
        )

    marca = marca_imitada(host)
    if marca:
        oficiais = ", ".join(marca.dominios_oficiais)
        adicionar(
            "dominio_imitando_marca",
            f"O endereço '{host}' contém o nome '{marca.nome}', mas não é "
            f"um domínio oficial da marca (oficial: {oficiais}).",
            30,
        )

    return sinais


def analisar_urls(texto: str) -> list[Sinal]:
    """Analisa todos os links do texto. Cada tipo de sinal aparece uma vez."""
    vistos: dict[str, Sinal] = {}
    for url in extrair_urls(texto):
        for sinal in analisar_url(url):
            vistos.setdefault(sinal.codigo, sinal)
    return list(vistos.values())