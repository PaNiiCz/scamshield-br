"""Erros próprios do ScamShield BR."""


class ScamShieldError(Exception):
    """Erro-base: todos os erros do projeto herdam deste."""

    def __init__(self, mensagem: str):
        self.mensagem = mensagem
        super().__init__(mensagem)


class EntradaInvalidaError(ScamShieldError):
    """O usuário enviou algo que não dá para analisar."""


class ServicoExternoError(ScamShieldError):
    """Uma fonte externa (VirusTotal, RDAP, etc.) falhou ou está fora do ar.

    Importante: quando isso acontece, a análise continua com o que já
    temos; só não ganhamos aquele sinal extra.
    """


class ConfiguracaoError(ScamShieldError):
    """Falta alguma configuração obrigatória (ex: chave de API)."""