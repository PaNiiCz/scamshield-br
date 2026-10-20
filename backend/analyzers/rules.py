"""Regras manuais de padrão de golpe em português brasileiro.

Cada regra procura um tipo de indício no texto e, se encontrar, gera um
Sinal. Este módulo NÃO decide se é golpe: apenas levanta os indícios.
Quem soma os pontos e decide o nível é o motor de risco.

Limitação conhecida: golpistas podem escrever de formas que fogem destes
padrões (ex: "p i x"). Por isso as regras são só uma peça do sistema,
junto com o modelo de ML e a inteligência externa.
"""

import re
import unicodedata
from dataclasses import dataclass

from backend.core.models import Sinal

ORIGEM = "rules"


def normalizar(texto: str) -> str:
    """Prepara o texto para comparação.

    - separa letras de acentos e descarta os acentos ("ç" vira "c")
    - descarta caracteres invisíveis (categoria Unicode "Cf")
    - põe tudo em minúsculas
    - troca qualquer sequência de espaços/quebras de linha por 1 espaço
    """
    decomposto = unicodedata.normalize("NFKD", texto)
    limpo = "".join(
        c
        for c in decomposto
        if not unicodedata.combining(c) and unicodedata.category(c) != "Cf"
    )
    return re.sub(r"\s+", " ", limpo.lower()).strip()


@dataclass(frozen=True)
class Regra:
    codigo: str
    descricao: str
    pontos: int
    padroes: tuple[str, ...]  # escritos SEM acento, em minúsculas
    forte: bool = False
    # Trechos "inofensivos" que são apagados do texto ANTES de aplicar
    # `padroes` (ex: avisos como "não compartilhe seu código").
    ignorar: tuple[str, ...] = ()
    # Padrões de PEDIDO direto ("informe o código"). Valem sempre, mesmo
    # que o texto tenha um aviso: golpista também escreve "não compartilhe".
    padroes_diretos: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Apoio da regra pedido_dados_sensiveis (Etapa 7.5)
# ---------------------------------------------------------------------------

# "Resto da frase": vai até o fim da frase, mas PARA em "mas/porém/...".
# Assim "não compartilhe com ninguém, mas informe o código" não apaga o
# pedido que vem depois do "mas".
_RESTO = r"(?:(?!\b(?:mas|porem|entretanto|contudo)\b)[^.!?;])*"

# Avisos de segurança: o texto está ALERTANDO, não pedindo.
_AVISOS_DE_SEGURANCA = (
    r"\b(?:nao|nunca|jamais) (?:compartilhe|compartilhar|informe|informar|"
    r"envie|enviar|passe|passar|forneca|fornecer|digite|digitar|fale|falar|"
    r"diga|dizer|repasse|repassar|mostre|divulgue|divulgar)\b" + _RESTO,
    r"\b(?:nao|nunca|jamais) (?:pedimos|solicitamos|pede|pedem|solicita|"
    r"solicitam|pediremos|solicitaremos|ligamos|enviamos)\b" + _RESTO,
    r"\bnenhum(?:a)?(?: \w+){1,4} (?:pedira|solicitara|ira pedir|vai pedir|"
    r"ira solicitar|vai solicitar)\b" + _RESTO,
    r"\bevite (?:compartilhar|informar|enviar|passar)\b" + _RESTO,
    r"\b(?:se|caso) (?:alguem|qualquer pessoa)\b[^.!?;]*?"
    r"\b(?:pedir|solicitar|pedirem|solicitarem|ligar)\b" + _RESTO,
)

# Mensagem que ENTREGA um código ("seu código é 123456"): o código está
# sendo enviado para você, ninguém está pedindo nada.
_ENTREGA_DE_CODIGO = (
    r"\b(?:codigo|token)(?: de (?:verificacao|seguranca|confirmacao|acesso))?"
    r"\s*(?:e|eh|:|-)?\s*\d{4,8}\b",
    r"\b\d{4,8}\s+(?:e|eh)\s+(?:o )?(?:seu )?(?:codigo|token)"
    r"(?: de (?:verificacao|seguranca|confirmacao|acesso))?",
)

# Pedido direto: "passa/envie/informe/mande ... código". Não vale quando
# vem logo depois de "não/nunca/jamais/nem" ("não informe o código").
_PEDIDO_DIRETO_DE_CODIGO = (
    r"(?<!\bnao )(?<!\bnunca )(?<!\bjamais )(?<!\bnem )"
    r"\b(?:passa|envie|informe|mande)\b.{0,25}\bcodigo\b",
)

REGRAS: tuple[Regra, ...] = (
    Regra(
        codigo="urgencia_falsa",
        descricao="A mensagem pressiona por ação imediata, tática comum "
        "para impedir que você pare e pense.",
        pontos=15,
        padroes=(
            r"\burgente\b",
            r"\bimediat",
            r"\bultimo aviso\b",
            r"\bultimas horas\b",
            r"\bso hoje\b",
            r"\bhoje (?:ainda|mesmo)\b",
            r"\bagora mesmo\b",
            r"\bem (?:ate )?\d+ ?(?:horas|h|minutos|min)\b",
            r"\bnao perca\b",
            r"\bevite (?:o )?(?:bloqueio|cancelamento|multa|corte)",
        ),
    ),
    Regra(
        codigo="ameaca_bloqueio",
        descricao="A mensagem ameaça bloquear, suspender, cancelar ou "
        "negativar algo seu para te assustar.",
        pontos=20,
        padroes=(
            r"\bbloquead[oa]",
            r"\bbloqueio\b",
            r"\bsuspens[ao]",
            r"\bsera (?:cancelad|bloquead|suspens)",
            r"\bcpf (?:irregular|cancelado|suspenso)",
            r"\bnegativad",
            r"\bprotesto\b",
            r"\bpenhora",
            r"\bacao judicial\b",
            r"\bcorte d[aoe]s? (?:energia|luz|agua|servico|linha)",
        ),
    ),
    Regra(
        codigo="pedido_pix",
        descricao="A mensagem pede PIX, transferência, depósito ou "
        "comprovante de pagamento.",
        pontos=20,
        padroes=(
            r"\bpix\b",
            r"\btransfer(?:a|ir|encia)\b",
            r"\bdeposit(?:e|ar|o)\b",
            r"\benvie (?:o )?comprovante\b",
        ),
    ),
    Regra(
        codigo="pedido_dados_sensiveis",
        descricao="A mensagem pede senha, código de verificação, dados de "
        "cartão ou foto de documento. Empresas sérias não pedem isso por "
        "mensagem.",
        pontos=30,
        forte=True,
        padroes=(
            r"\bsenha\b",
            r"\bcvv\b",
            r"\btoken\b",
            r"\bcodigo (?:de )?(?:verificacao|seguranca|confirmacao|sms)\b",
            r"\bcodigo que (?:voce )?(?:recebeu|chegou|enviamos)\b",
            r"\bdados (?:do )?(?:cartao|bancarios)\b",
            r"\bnumero do cartao\b",
            r"\bfoto (?:do |de )?(?:documento|rg|cnh)\b",
            r"\bselfie\b",
        ),
        ignorar=_AVISOS_DE_SEGURANCA + _ENTREGA_DE_CODIGO,
        padroes_diretos=_PEDIDO_DIRETO_DE_CODIGO,
    ),
    Regra(
        codigo="falso_parente",
        descricao="A mensagem usa o roteiro do 'parente com número novo': "
        "troca de número, celular perdido ou chamada por parentesco.",
        pontos=25,
        padroes=(
            r"\bmudei de numero\b",
            r"\bnovo numero\b",
            r"\btrocei de (?:numero|celular|chip)\b",
            r"\bperdi (?:meu )?(?:celular|telefone|chip)\b",
            r"\bsalv[ae] (?:meu |esse |o )?(?:novo )?numero\b",
            r"\b(?:oi|ola),? (?:mae|pai|vo|vovo|tio|tia|filho|filha)\b",
            r"\bcelular quebr",
        ),
    ),
    Regra(
        codigo="emergencia_familiar",
        descricao="A mensagem cita emergência (acidente, hospital, "
        "sequestro) para gerar pânico.",
        pontos=10,
        padroes=(
            r"\bacidente\b",
            r"\bhospital\b",
            r"\bsequestr",
            r"\bpreso\b",
            r"\bemergencia\b",
            r"\bdelegacia\b",
        ),
    ),
    Regra(
        codigo="promessa_premio",
        descricao="A mensagem promete prêmio, restituição ou dinheiro "
        "esquecido, isca clássica de golpe.",
        pontos=20,
        padroes=(
            r"\bvoce (?:ganhou|foi (?:sorteado|selecionado|contemplado))",
            r"\bparabens\b.{0,40}\b(?:ganhou|premio|sorteio|selecionado)",
            r"\bpremio\b",
            r"\bsorteio\b",
            r"\brestituicao\b",
            r"\bvalores? (?:a|para) (?:receber|resgatar|sacar)\b",
            r"\bfgts\b.{0,30}\b(?:liberad|saque)",
            r"\bcashback\b",
            r"\bheranca\b",
        ),
    ),
    Regra(
        codigo="cobranca_pendente",
        descricao="A mensagem cobra fatura, débito ou boleto atrasado, "
        "roteiro frequente de falsa operadora ou banco.",
        pontos=15,
        padroes=(
            r"\bfatura\b.{0,40}\b(?:atras|vencid|pendent|aberto)",
            r"\bdebito\b.{0,30}\b(?:pendente|em aberto|atrasado)",
            r"\bboleto\b.{0,30}\b(?:vencido|atrasado|pendente)",
            r"\b(?:regularize|quite)\b",
            r"\bsegunda via\b",
        ),
    ),
    Regra(
        codigo="pedido_sigilo",
        descricao="A mensagem pede segredo ('não conte para ninguém'), "
        "para isolar você de quem poderia alertar.",
        pontos=15,
        padroes=(
            r"\bnao (?:conte|comente|fale) (?:para|pra|com) ninguem\b",
            r"\bsigilo\b",
            r"\bsegredo\b",
            r"\bnao (?:avise|diga)\b",
        ),
    ),
    Regra(
        codigo="instalar_app_ou_acesso_remoto",
        descricao="A mensagem pede para instalar um aplicativo ou liberar "
        "acesso remoto ao seu aparelho.",
        pontos=25,
        forte=True,
        padroes=(
            r"\b(?:instale|instalar|baixe|baixar)\b.{0,30}"
            r"\b(?:aplicativo|app|programa|arquivo)\b",
            r"\.apk\b",
            r"\banydesk\b",
            r"\bteamviewer\b",
            r"\bacesso remoto\b",
        ),
    ),
    Regra(
        codigo="pagamento_antecipado",
        descricao="A mensagem pede que você pague uma taxa antes de "
        "receber algo. Golpe de 'pagamento antecipado'.",
        pontos=25,
        forte=True,
        padroes=(
            r"\btaxa\b.{0,30}\b(?:liberar|liberacao|desbloque|saque|emissao)",
            r"\bpague\b.{0,30}\b(?:para|pra) (?:liberar|receber|desbloquear)",
            r"\bpara liberar\b.{0,40}\b(?:pix|pague|taxa|valor)",
        ),
    ),
)

# Compila todos os padrões uma única vez, quando o módulo é carregado.
_COMPILADAS: dict[str, list[re.Pattern[str]]] = {
    regra.codigo: [re.compile(p) for p in regra.padroes] for regra in REGRAS
}
_COMPILADAS_DIRETAS: dict[str, list[re.Pattern[str]]] = {
    regra.codigo: [re.compile(p) for p in regra.padroes_diretos] for regra in REGRAS
}
_COMPILADAS_IGNORAR: dict[str, list[re.Pattern[str]]] = {
    regra.codigo: [re.compile(p) for p in regra.ignorar] for regra in REGRAS
}


def _sem_trechos_inofensivos(codigo: str, texto: str) -> str:
    """Apaga do texto os trechos que a regra deve ignorar (avisos etc.)."""
    for padrao in _COMPILADAS_IGNORAR[codigo]:
        texto = padrao.sub(" ", texto)
    return texto


def analisar_regras(texto: str) -> list[Sinal]:
    """Procura os padrões de golpe no texto e devolve os sinais achados.

    Cada regra gera no máximo UM sinal, mesmo que o padrão apareça
    várias vezes no texto.
    """
    normalizado = normalizar(texto)
    sinais: list[Sinal] = []
    for regra in REGRAS:
        limpo = _sem_trechos_inofensivos(regra.codigo, normalizado)
        achou = any(p.search(limpo) for p in _COMPILADAS[regra.codigo]) or any(
            p.search(normalizado) for p in _COMPILADAS_DIRETAS[regra.codigo]
        )
        if achou:
            sinais.append(
                Sinal(
                    codigo=regra.codigo,
                    descricao=regra.descricao,
                    pontos=regra.pontos,
                    origem=ORIGEM,
                    forte=regra.forte,
                )
            )
    return sinais