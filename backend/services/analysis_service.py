"""Orquestrador da análise.

Recebe a mensagem, chama os analisadores adequados, entrega os sinais
ao motor de risco e monta o resultado final.

Analisadores ativos: regras (Etapa 3), URLs (Etapa 5), modelo de texto
(Etapa 6), cabeçalhos de e-mail (Etapa 7, só no canal e-mail), OSINT
passivo (Etapa 8), letras falsas (Etapa 8.5) e VirusTotal (Etapa 9).
Nas próximas etapas, os demais entram na lista de sinais aqui.
"""

from backend.analyzers.email_header_analyzer import analisar_cabecalhos
from backend.analyzers.homoglyph_analyzer import analisar_homoglifos, desfazer_confusiveis
from backend.analyzers.rules import analisar_regras
from backend.analyzers.scam_types import NOMES_AMIGAVEIS, classificar_tipo
from backend.analyzers.text_classifier import analisar_ml
from backend.analyzers.url_analyzer import analisar_urls
from backend.core.models import (
    Canal,
    MensagemEntrada,
    NivelRisco,
    ResultadoAnalise,
    Sinal,
    TipoGolpe,
)
from backend.osint.osint_service import analisar_osint
from backend.risk.risk_engine import calcular_risco
from backend.threat_intel.virustotal_client import analisar_virustotal


def _montar_resumo(
    nivel: NivelRisco,
    qtd_sinais: int,
    motivo: str | None,
    tipo: TipoGolpe | None,
) -> str:
    sinais = "sinal" if qtd_sinais == 1 else "sinais"

    if nivel == NivelRisco.VERDE:
        resumo = (
            "Não encontramos sinais fortes de golpe nesta mensagem. "
            "Isso não garante que ela seja segura: na dúvida, confirme "
            "pelo canal oficial da empresa."
        )
    elif nivel == NivelRisco.LARANJA:
        resumo = (
            f"Mensagem suspeita: encontramos {qtd_sinais} {sinais} de golpe. "
            "Não responda, não clique em links e confirme pelo canal oficial."
        )
    else:
        resumo = (
            f"Alto risco: encontramos {qtd_sinais} {sinais} de golpe. "
            "Não pague, não envie dados e não clique em links. "
            "Confirme pelo canal oficial da empresa."
        )

    if tipo in NOMES_AMIGAVEIS:
        resumo += f" Tipo provável: {NOMES_AMIGAVEIS[tipo]}."
    if motivo:
        resumo += f" Nível mínimo aplicado por regra de segurança: {motivo}."
    return resumo


def analisar_mensagem(mensagem: MensagemEntrada) -> ResultadoAnalise:
    """Analisa uma mensagem e devolve o resultado explicável."""
    sinais: list[Sinal] = []

    # Letras de outros alfabetos que imitam letras latinas ("а" cirílico = 1072,
    # "a" latino = 97) são trocadas pelas latinas ANTES das regras, do modelo e
    # do analisador de URLs. Assim "рix" volta a ser "pix" e "clаro-fatura.xyz"
    # volta a imitar a Claro. O texto ORIGINAL segue para o analisador de
    # letras falsas e para o OSINT (que precisa do endereço verdadeiro).
    texto_limpo = desfazer_confusiveis(mensagem.texto)

    # Cada analisador é chamado UMA vez.
    sinais.extend(analisar_regras(texto_limpo))
    sinais.extend(analisar_urls(texto_limpo))
    sinais.extend(analisar_ml(texto_limpo))
    sinais.extend(analisar_homoglifos(mensagem.texto))

    # OSINT passivo (Etapa 8): consulta só o DOMÍNIO dos links a fontes
    # públicas. Se estiver desligado ou as fontes falharem, devolve [].
    sinais.extend(analisar_osint(mensagem.texto))

    # VirusTotal (Etapa 9): só com chave no .env. Pergunta só pelo DOMÍNIO.
    sinais.extend(analisar_virustotal(mensagem.texto))

    # Cabeçalhos só fazem sentido para e-mail. O corpo do e-mail já passou
    # pelos analisadores acima.
    if mensagem.canal == Canal.EMAIL and mensagem.cabecalhos_email:
        sinais.extend(analisar_cabecalhos(mensagem.cabecalhos_email))

    # Sinais mais pesados primeiro: o usuário vê o que mais importa no topo.
    sinais.sort(key=lambda s: s.pontos, reverse=True)

    veredito = calcular_risco(sinais)

    # Só classificamos o tipo quando há motivo para desconfiar.
    tipo = None
    if veredito.nivel != NivelRisco.VERDE:
        tipo = classificar_tipo(texto_limpo, sinais)

    return ResultadoAnalise(
        pontuacao=veredito.pontuacao,
        nivel=veredito.nivel,
        sinais=sinais,
        tipo_golpe=tipo,
        resumo=_montar_resumo(
            veredito.nivel, len(sinais), veredito.motivo_forcado, tipo
        ),
    )