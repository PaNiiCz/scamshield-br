"""Analisador de cabeçalhos de e-mail do ScamShield BR.

Lê os cabeçalhos colados pelo usuário e procura sinais de falsificação.
É totalmente passivo: não consulta DNS nem se conecta a nenhum servidor.
Só lê o que o servidor RECEPTOR já escreveu em Authentication-Results
(ou Received-SPF).

Limitações conhecidas:
- Cabeçalhos colados e editados à mão não são verificáveis. O sistema
  confia no que foi colado.
- Usamos só o Authentication-Results mais de cima, que é o do servidor
  que recebeu a mensagem. Os de baixo podem ter sido escritos por quem
  enviou.
- Return-Path e Reply-To diferentes existem em e-mails legítimos
  (newsletters, plataformas de envio). Por isso valem poucos pontos.

Privacidade: as descrições dos sinais mostram só o DOMÍNIO, nunca o
endereço completo.
"""

import re
import unicodedata
from email import message_from_string
from email.message import Message
from email.policy import default as politica_padrao
from email.utils import parseaddr

from backend.analyzers.url_analyzer import (
    MARCAS,
    dominio_registrado,
    e_oficial,
    marca_imitada,
    tem_punycode,
    tem_tld_suspeito,
)
from backend.core.models import Sinal

ORIGEM = "email_header_analyzer"

# Se nenhum destes cabeçalhos existir, o texto colado não parece um
# cabeçalho de e-mail.
_CABECALHOS_CONHECIDOS = (
    "from", "reply-to", "return-path", "authentication-results",
    "received-spf", "received", "subject", "to", "date", "message-id",
)

# Palavras comuns em nomes de exibição de empresas. Servem para separar
# "TIM Atendimento" (empresa) de "Tim Silva" (pessoa).
_PALAVRAS_GENERICAS = frozenset(
    {
        "atendimento", "suporte", "oficial", "sac", "cliente", "clientes",
        "fatura", "faturas", "seguranca", "contato", "cobranca", "banco",
        "app", "servico", "servicos", "central", "brasil", "br", "noreply",
        "no", "reply", "aviso", "avisos", "alerta", "alertas", "de", "do",
        "da", "e", "cartoes", "cartao", "conta", "digital",
    }
)

_RE_RESULTADO = {
    nome: re.compile(rf"\b{nome}\s*=\s*([a-z]+)")
    for nome in ("spf", "dkim", "dmarc")
}
_RE_RECEIVED_SPF = re.compile(r"^\s*([a-z]+)")


# ---------------------------------------------------------------------------
# Auxiliares
# ---------------------------------------------------------------------------


def _sem_acento(texto: str) -> str:
    decomposto = unicodedata.normalize("NFKD", texto.lower())
    return "".join(c for c in decomposto if not unicodedata.combining(c))


def _primeiro(msg: Message, nome: str) -> str:
    """Valor do primeiro cabeçalho com esse nome (o mais de cima)."""
    valores = msg.get_all(nome) or []
    return str(valores[0]) if valores else ""


def _separar_endereco(valor: str) -> tuple[str, str]:
    """Devolve (nome_de_exibicao, dominio_em_minusculas)."""
    nome, endereco = parseaddr(valor)
    if "@" not in endereco:
        return nome, ""
    dominio = endereco.rpartition("@")[2].strip().strip(">").lower()
    return nome, dominio


def _resultado(msg: Message, mecanismo: str) -> set[str]:
    """Resultados (pass, fail...) de spf/dkim/dmarc no cabeçalho de cima."""
    topo = _primeiro(msg, "authentication-results").lower()
    return set(_RE_RESULTADO[mecanismo].findall(topo))


def _resultado_spf(msg: Message) -> str | None:
    """SPF vem do Authentication-Results; se faltar, do Received-SPF."""
    achados = _resultado(msg, "spf")
    if achados:
        for ruim in ("fail", "softfail"):
            if ruim in achados:
                return ruim
        return next(iter(achados))
    correspondencia = _RE_RECEIVED_SPF.match(_primeiro(msg, "received-spf").lower())
    return correspondencia.group(1) if correspondencia else None


def _nome_imita_marca(nome_exibicao: str) -> str | None:
    """Nome da marca citada no nome de exibição, ou None."""
    normalizado = _sem_acento(nome_exibicao)
    pedacos = re.findall(r"[a-z0-9]+", normalizado)
    if not pedacos:
        return None
    compacto = "".join(pedacos)

    for marca in MARCAS:
        for palavra in marca.palavras:
            if len(palavra) >= 5:
                if palavra in compacto:
                    return marca.nome
            elif palavra in pedacos:
                # Palavra curta (tim, vivo, itau): só conta se o resto do
                # nome for "de empresa". "Tim Silva" não conta.
                resto = [p for p in pedacos if p != palavra]
                if all(p in _PALAVRAS_GENERICAS for p in resto):
                    return marca.nome
    return None


# ---------------------------------------------------------------------------
# Função principal
# ---------------------------------------------------------------------------


def analisar_cabecalhos(cabecalhos: str) -> list[Sinal]:
    """Analisa cabeçalhos de e-mail. Nunca lança exceção por entrada ruim."""
    if not cabecalhos or not cabecalhos.strip():
        return []

    sinais: list[Sinal] = []

    def adicionar(codigo: str, descricao: str, pontos: int) -> None:
        sinais.append(
            Sinal(codigo=codigo, descricao=descricao, pontos=pontos, origem=ORIGEM)
        )

    try:
        msg = message_from_string(cabecalhos.strip(), policy=politica_padrao)
        conhecidos = [nome for nome in msg.keys() if nome.lower() in _CABECALHOS_CONHECIDOS]
        if not conhecidos:
            raise ValueError("nenhum cabecalho reconhecido")

        # --- SPF, DKIM e DMARC -------------------------------------------
        spf = _resultado_spf(msg)
        if spf == "fail":
            adicionar(
                "remetente_spf_falhou",
                "O servidor que recebeu o e-mail registrou falha no SPF: o "
                "servidor que enviou não tinha permissão para usar esse "
                "domínio.",
                25,
            )
        elif spf == "softfail":
            adicionar(
                "remetente_spf_falhou",
                "O servidor que recebeu o e-mail registrou uma falha leve "
                "no SPF: o servidor que enviou provavelmente não tinha "
                "permissão para usar esse domínio.",
                15,
            )

        dkim = _resultado(msg, "dkim")
        if "fail" in dkim and "pass" not in dkim:
            adicionar(
                "dkim_falhou",
                "A assinatura digital (DKIM) do e-mail não confere: a "
                "mensagem pode ter sido alterada ou falsificada.",
                20,
            )

        dmarc = _resultado(msg, "dmarc")
        if "fail" in dmarc:
            adicionar(
                "dmarc_falhou",
                "O e-mail falhou na política DMARC do domínio do remetente, "
                "que serve justamente para barrar falsificações.",
                20,
            )

        # --- Remetente ---------------------------------------------------
        nome_exibicao, dominio_from = _separar_endereco(_primeiro(msg, "from"))

        if dominio_from:
            registrado_from = dominio_registrado(dominio_from)

            _, dominio_reply = _separar_endereco(_primeiro(msg, "reply-to"))
            if dominio_reply and dominio_registrado(dominio_reply) != registrado_from:
                adicionar(
                    "reply_to_diferente",
                    f"Se você responder, a resposta vai para '{dominio_reply}', "
                    f"que não é o domínio do remetente ('{dominio_from}').",
                    20,
                )

            _, dominio_retorno = _separar_endereco(_primeiro(msg, "return-path"))
            if dominio_retorno and dominio_registrado(dominio_retorno) != registrado_from:
                adicionar(
                    "return_path_diferente",
                    f"O endereço de retorno técnico ('{dominio_retorno}') é de "
                    f"outro domínio, diferente do remetente ('{dominio_from}').",
                    10,
                )

            if not e_oficial(dominio_from):
                marca_no_nome = _nome_imita_marca(nome_exibicao)
                if marca_no_nome:
                    adicionar(
                        "nome_exibicao_imitando_marca",
                        f"O nome do remetente cita '{marca_no_nome}', mas o "
                        f"e-mail vem de '{dominio_from}', que não é um domínio "
                        "oficial da marca.",
                        30,
                    )

                marca = marca_imitada(dominio_from)
                if marca:
                    adicionar(
                        "dominio_remetente_imitando_marca",
                        f"O domínio do remetente ('{dominio_from}') contém o "
                        f"nome '{marca.nome}', mas não é um domínio oficial "
                        "da marca.",
                        30,
                    )

                if tem_tld_suspeito(dominio_from) or tem_punycode(dominio_from):
                    adicionar(
                        "dominio_remetente_suspeito",
                        f"O domínio do remetente ('{dominio_from}') usa um "
                        "final ou uma codificação muito comum em golpes.",
                        10,
                    )

    except Exception:  # cabeçalho ilegível não pode virar erro da API
        return [
            Sinal(
                codigo="cabecalhos_invalidos",
                descricao=(
                    "Não foi possível ler os cabeçalhos informados, então "
                    "essa parte da análise não pôde ser feita."
                ),
                pontos=5,
                origem=ORIGEM,
            )
        ]

    return sinais