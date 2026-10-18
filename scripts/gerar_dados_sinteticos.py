"""Gerador de dados SINTÉTICOS para treinar o classificador de texto.

Cria mensagens de golpe (rótulo 1) e mensagens legítimas (rótulo 0) a
partir de modelos (templates) com campos que variam (marca, valor, prazo...).

ATENÇÃO - limitação importante: como os dados são fabricados a partir de
modelos, o classificador aprende o "jeito" destes modelos, e não o jeito
dos golpes reais. As métricas medidas aqui são OTIMISTAS. O dataset real
e a avaliação cega ficam para a Fase 2 do projeto.

Para medir de forma menos enganosa, a divisão treino/teste é feita por
MODELO: alguns modelos inteiros ficam de fora do treino e só aparecem no
teste. Assim o teste mede se o classificador reconhece golpes de um
formato que ele nunca viu.

Uso (na raiz do projeto):
    python -m scripts.gerar_dados_sinteticos
"""

import csv
import random
import unicodedata
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
CAMINHO_CSV = RAIZ / "data" / "synthetic" / "mensagens.csv"

# ---------------------------------------------------------------------------
# Valores que preenchem os campos dos modelos
# ---------------------------------------------------------------------------
OPERADORAS = ["Claro", "Vivo", "TIM", "Oi"]
BANCOS = ["Itaú", "Bradesco", "Santander", "Nubank", "Caixa", "Banco do Brasil", "Inter"]
NOMES = ["Ana", "João", "Carlos", "Mariana", "Pedro", "Juliana", "Lucas", "Fernanda"]
LOJAS = ["Magazine Luiza", "Americanas", "Shopee", "Amazon", "Mercado Livre", "Renner"]
MESES = ["janeiro", "março", "maio", "julho", "setembro", "outubro", "novembro"]
PARENTES = ["mãe", "pai", "tio", "tia", "vó", "vô"]
PRAZOS = ["hoje", "em 24 horas", "em 2 horas", "até as 18h", "amanhã cedo"]
HORAS = ["8h", "9h30", "14h", "16h", "19h"]
DOUTORES = ["Dra. Paula", "Dr. Ricardo", "Dra. Helena", "Dr. Marcos"]
ATIVIDADES = ["almoçar", "tomar um café", "jantar", "estudar", "jogar bola", "ir ao cinema"]
QUANDOS = ["amanhã", "hoje", "no sábado", "depois do trabalho", "no fim de semana"]
MARCAS_FALSAS = ["claro", "vivo", "itau", "bradesco", "nubank", "caixa", "correios", "serasa"]
PALAVRAS_FALSAS = ["fatura", "segura", "atualiza", "regulariza", "acesso", "desbloqueio"]
TLDS_FALSOS = ["xyz", "top", "click", "icu", "site", "online"]
LINKS_OFICIAIS = [
    "https://www.claro.com.br",
    "https://www.itau.com.br",
    "https://www.nubank.com.br",
    "https://www.correios.com.br",
    "https://www.mercadolivre.com.br",
]


def _milhar(numero: int) -> str:
    return f"{numero:,}".replace(",", ".")


_GERADORES = {
    "operadora": lambda r: r.choice(OPERADORAS),
    "banco": lambda r: r.choice(BANCOS),
    "nome": lambda r: r.choice(NOMES),
    "loja": lambda r: r.choice(LOJAS),
    "mes": lambda r: r.choice(MESES),
    "parente": lambda r: r.choice(PARENTES),
    "prazo": lambda r: r.choice(PRAZOS),
    "hora": lambda r: r.choice(HORAS),
    "dr": lambda r: r.choice(DOUTORES),
    "atividade": lambda r: r.choice(ATIVIDADES),
    "quando": lambda r: r.choice(QUANDOS),
    "dia": lambda r: str(r.randint(1, 28)),
    "valor": lambda r: f"R$ {r.randint(20, 900)},{r.choice(['90', '00', '50', '99'])}",
    "valor_pequeno": lambda r: f"R$ {r.randint(19, 149)},{r.choice(['90', '00'])}",
    "valor_grande": lambda r: f"R$ {_milhar(r.choice([2000, 3500, 5000, 8000, 10000, 15000, 20000]))}",
    "cod6": lambda r: str(r.randint(100000, 999999)),
    "cod4": lambda r: str(r.randint(1000, 9999)),
    "protocolo": lambda r: str(r.randint(10**9, 10**10 - 1)),
    "rastreio": lambda r: f"AB{r.randint(100000000, 999999999)}BR",
    "pedido": lambda r: f"#{r.randint(10000, 99999)}",
    "link_falso": lambda r: (
        f"{r.choice(['http', 'https'])}://{r.choice(MARCAS_FALSAS)}-"
        f"{r.choice(PALAVRAS_FALSAS)}.{r.choice(TLDS_FALSOS)}/"
        f"{''.join(r.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=5))}"
    ),
    "link_oficial": lambda r: r.choice(LINKS_OFICIAIS),
}


class _Preenchimento(dict):
    """Preenche os campos {assim} de um modelo, mantendo o valor já sorteado."""

    def __init__(self, rng: random.Random):
        super().__init__()
        self._rng = rng

    def __missing__(self, chave: str) -> str:
        valor = _GERADORES[chave](self._rng)
        self[chave] = valor
        return valor


# ---------------------------------------------------------------------------
# Modelos de mensagens de GOLPE (rótulo 1)
# ---------------------------------------------------------------------------
TEMPLATES_GOLPE = [
    "{operadora}: sua fatura de {valor} está em atraso e sua linha será bloqueada {prazo}. Regularize agora: {link_falso}",
    "{operadora} informa: débito pendente de {valor}. Evite o corte do serviço, pague via PIX: {link_falso}",
    "{banco}: identificamos acesso suspeito na sua conta. Para evitar o bloqueio, atualize seus dados em {link_falso}",
    "Seu acesso ao {banco} foi suspenso. Confirme sua senha e o código SMS que enviamos para reativar: {link_falso}",
    "ATENÇÃO {banco}: seu cartão foi bloqueado por segurança. Desbloqueie {prazo} em {link_falso}",
    "Oi {parente}, mudei de número. Salva esse novo e me chama no zap. Perdi meu celular",
    "Oi {parente}, meu celular quebrou e estou usando esse número. Preciso que você faça um PIX de {valor} urgente, depois te explico",
    "Oi {parente}, tudo bem? Esse é meu número novo. Consegue me ajudar com um pagamento de {valor} hoje? Te devolvo amanhã",
    "Parabéns {nome}! Você foi sorteado e ganhou um prêmio de {valor_grande}. Resgate agora em {link_falso}",
    "Receita Federal: você tem restituição de {valor_grande} disponível. Consulte seu CPF em {link_falso} antes que expire",
    "Seu FGTS tem valores liberados para saque. Para receber, pague a taxa de liberação de {valor_pequeno} via PIX",
    "Para liberar seu empréstimo aprovado de {valor_grande} é necessário pagar uma taxa de {valor_pequeno}. Envie o comprovante",
    "Para resolver o problema na sua conta {banco}, baixe o aplicativo AnyDesk e me passe o código de acesso",
    "Correios: sua encomenda está retida. Pague a taxa de {valor_pequeno} para liberar a entrega: {link_falso}",
    "Segunda via do boleto vencido {banco}. Pague {prazo} para evitar protesto e negativação no Serasa: {link_falso}",
    "Seu CPF será negativado no Serasa {prazo}. Negocie sua dívida com desconto de 90%: {link_falso}",
    "Oportunidade de trabalho home office, ganhe até {valor_grande} por mês. Chame no WhatsApp agora, vagas limitadas",
    "Oi, mandei um código no seu WhatsApp por engano, pode me passar? É urgente",
    "Olá, tenho interesse no seu anúncio. Vou pagar adiantado, só preciso que me informe o código que enviamos por SMS",
    "Fiz um PIX de {valor} para você por engano, pode devolver? Já te mando o comprovante",
    "INSS: benefício bloqueado. Regularize seu cadastro com urgência: {link_falso}",
    "Seu filho sofreu um acidente e está no hospital. Precisa de um depósito de {valor} agora, não conte para ninguém",
    "Seu WhatsApp será desativado {prazo}. Confirme sua conta em {link_falso}",
    "Invista {valor_pequeno} e receba {valor_grande} em 24 horas. Lucro garantido sem risco, chame agora",
    "{banco}: compra de {valor} não reconhecida? Cancele agora antes que seja debitada em {link_falso}",
    "Você tem uma intimação pendente em seu nome. Acesse {link_falso} {prazo} para evitar multa",
    "PIX: sua chave será excluída {prazo}. Confirme seus dados em {link_falso}",
]

# ---------------------------------------------------------------------------
# Modelos de mensagens LEGÍTIMAS (rótulo 0)
# ---------------------------------------------------------------------------
TEMPLATES_LEGITIMAS = [
    "Seu pedido {pedido} foi enviado e chega em até 3 dias úteis. Acompanhe pelo app.",
    "Olá {nome}, seu pedido da {loja} foi entregue hoje. Obrigado por comprar conosco!",
    "{operadora}: sua fatura de {mes} no valor de {valor} já está disponível no app. Vencimento dia {dia}. Veja em {link_oficial}",
    "Recebemos o pagamento da sua fatura de {mes}. Obrigado!",
    "Seu código de verificação é {cod6}. Não compartilhe com ninguém.",
    "Oi, tudo bem? Vamos {atividade} {quando}?",
    "Reunião de alinhamento amanhã às {hora}. Confirma presença?",
    "Lembrete: sua consulta com {dr} é amanhã às {hora}. Responda 1 para confirmar.",
    "Compra aprovada no cartão final {cod4} no valor de {valor} na {loja}. Não reconhece? Ligue para o número no verso do cartão.",
    "{loja}: aproveite 20% de desconto em toda a loja neste fim de semana. Confira no app.",
    "Fechado, vou te mandar o PIX do ingresso depois do jogo. Pode me passar sua chave quando puder?",
    "Reunião de pais na sexta às 19h. Contamos com a presença de todos.",
    "{banco}: por segurança, nunca pedimos sua senha ou códigos por mensagem. Dúvidas, acesse o app oficial.",
    "Seu código de retirada é {cod4}. Apresente no balcão da loja.",
    "Pessoal, o churrasco será domingo às 13h. Cada um leva uma bebida.",
    "Olá {nome}, recebemos seu currículo para a vaga de analista. Entraremos em contato nos próximos dias.",
    "Correios: seu objeto saiu para entrega. Acompanhe pelo código de rastreio {rastreio} em {link_oficial}",
    "Lembrete amigável: seu boleto vence dia {dia}. Pague pelo app do seu banco.",
    "Sua conta de energia de {mes} já está disponível. Vencimento: dia {dia}. Pague pelo app ou em casas lotéricas.",
    "Obrigado pelo contato! Seu protocolo de atendimento é {protocolo}.",
    "Bom dia! Você viu o jogo ontem?",
    "{parente}, cheguei bem em casa. Beijo!",
    "Valeu pela ajuda ontem, {nome}! Me salvou.",
    "Não esquece de trazer o notebook amanhã, combinado?",
    "Preciso de ajuda com o trabalho da faculdade, tem tempo hoje?",
    "Bom dia! Tudo bem?",
    "Oi! Tudo bem por aí? Faz tempo que a gente não se fala.",
    "Boa noite, {nome}! Como foi o seu dia?",
    "Pode me ligar quando chegar em casa?",
    "Já saí de casa, chego em 15 minutos.",
    "Parabéns pelo aniversário, {nome}! Muita saúde e felicidade.",
    "Bora {atividade} {quando}?",
    "{nome}, o PIX do mercado deu {valor}. Me manda o seu quando puder.",
    "Sua fatura da {operadora} de {mes} chegou. Acesse {link_oficial} para ver os detalhes.",
    "Rastreie seu pedido da {loja} em {link_oficial}. Previsão de entrega: {quando}.",
    "Obrigado pela indicação, {nome}! Vou ligar para ele hoje.",
    "Oi, tudo bem? Pode me mandar o endereço do restaurante?",
]


# ---------------------------------------------------------------------------
# Ruído: variações de escrita que acontecem no mundo real
# ---------------------------------------------------------------------------
def _sem_acentos(texto: str) -> str:
    decomposto = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in decomposto if not unicodedata.combining(c))


def _ruido(texto: str, rng: random.Random) -> str:
    # O mesmo ruído vale para os dois tipos de mensagem, para o modelo
    # não aprender "emoji = golpe" ou "maiúscula = golpe" por acaso.
    sorteio = rng.random()
    if sorteio < 0.15:
        texto = texto.lower()
    elif sorteio < 0.25:
        texto = texto.upper()
    if rng.random() < 0.20:
        texto = _sem_acentos(texto)
    if rng.random() < 0.20:
        texto += rng.choice([" 🙏", " 😊", " 🚨", " ⚠️", " !!", " ..."])
    if rng.random() < 0.15:
        texto = rng.choice(["Olá! ", "Atenção: ", "Oi, ", "Bom dia. ", "Boa tarde! "]) + texto
    return texto


def gerar_dataset(variantes_por_template: int = 40, semente: int = 42) -> list[dict]:
    """Gera as linhas do dataset (reprodutível: mesma semente, mesmo resultado)."""
    rng = random.Random(semente)
    linhas: list[dict] = []
    grupo = 0

    for rotulo, templates in ((1, TEMPLATES_GOLPE), (0, TEMPLATES_LEGITIMAS)):
        for indice, template in enumerate(templates):
            # Um em cada cinco modelos fica reservado para o TESTE.
            particao = "teste" if indice % 5 == 0 else "treino"

            textos: list[str] = []
            tentativas = 0
            while len(textos) < variantes_por_template and tentativas < variantes_por_template * 10:
                tentativas += 1
                texto = _ruido(template.format_map(_Preenchimento(rng)), rng)
                if texto not in textos:
                    textos.append(texto)

            for texto in textos:
                linhas.append(
                    {"texto": texto, "rotulo": rotulo, "grupo": grupo, "particao": particao}
                )
            grupo += 1

    rng.shuffle(linhas)
    return linhas


def salvar_csv(linhas: list[dict], caminho: Path = CAMINHO_CSV) -> None:
    caminho.parent.mkdir(parents=True, exist_ok=True)
    with caminho.open("w", encoding="utf-8", newline="") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=["texto", "rotulo", "grupo", "particao"])
        escritor.writeheader()
        escritor.writerows(linhas)


if __name__ == "__main__":
    dataset = gerar_dataset()
    salvar_csv(dataset)
    total = len(dataset)
    golpes = sum(1 for linha in dataset if linha["rotulo"] == 1)
    teste = sum(1 for linha in dataset if linha["particao"] == "teste")
    print(f"Dataset salvo em: {CAMINHO_CSV}")
    print(f"Total: {total} mensagens | golpes: {golpes} | legítimas: {total - golpes}")
    print(f"Treino: {total - teste} | Teste (modelos nunca vistos): {teste}")