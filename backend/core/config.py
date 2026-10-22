"""Configurações centrais do ScamShield BR.

Lê valores do arquivo .env (ou de variáveis de ambiente) e os entrega
validados num único objeto. Nenhum segredo fica escrito no código.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Identidade do app ---
    app_name: str = "ScamShield BR"

    # --- Segredos e caminhos (vêm do .env) ---
    virustotal_api_key: str = ""
    database_path: str = "data/scamshield.db"
    log_level: str = "INFO"

    # --- Limiares do motor de risco (pontuação de 0 a 100) ---
    # 0-29 = verde | 30-59 = laranja | 60-100 = vermelho
    limiar_suspeito: int = 30
    limiar_alto_risco: int = 60

    # --- Limite de tamanho da mensagem analisada (proteção contra abuso) ---
    tamanho_maximo_mensagem: int = 10_000

    # --- OSINT passivo (Etapa 8) ---
    # Consulta fontes públicas (RDAP, Archive.org) sobre o DOMÍNIO dos links.
    # Só o domínio sai da sua máquina, nunca o texto da mensagem. Mesmo assim,
    # quem recebe a consulta fica sabendo qual domínio foi pesquisado, por
    # isso dá para desligar com OSINT_ATIVADO=false no arquivo .env.
    osint_ativado: bool = True
    osint_timeout_segundos: float = 5.0
    osint_max_dominios: int = 3

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # ignora variáveis do .env que não conhecemos
    )


@lru_cache
def get_settings() -> Settings:
    """Devolve sempre o mesmo objeto de configurações.

    O @lru_cache faz a leitura do .env acontecer uma única vez;
    nas chamadas seguintes o resultado já está guardado.
    """
    return Settings()