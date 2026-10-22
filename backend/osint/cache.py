"""Cache em memória com validade, para não repetir consultas a terceiros."""

import threading
import time
from collections import OrderedDict
from typing import Any, Callable


class CacheTTL:
    """Guarda valores por um tempo limitado e descarta o mais antigo se encher.

    Guarda também o valor None ("consultamos e não há dado"), para não
    repetir uma consulta que já sabemos que não ajuda.
    """

    def __init__(
        self,
        validade_segundos: float,
        tamanho_maximo: int = 512,
        relogio: Callable[[], float] = time.monotonic,
    ):
        self._validade = validade_segundos
        self._maximo = tamanho_maximo
        self._relogio = relogio
        self._dados: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._trava = threading.Lock()  # várias threads usam o mesmo cache

    def guardar(self, chave: str, valor: Any) -> None:
        with self._trava:
            self._dados[chave] = (self._relogio() + self._validade, valor)
            self._dados.move_to_end(chave)
            while len(self._dados) > self._maximo:
                self._dados.popitem(last=False)

    def buscar(self, chave: str) -> tuple[bool, Any]:
        """Devolve (achou, valor). Valor vencido conta como não achado."""
        with self._trava:
            item = self._dados.get(chave)
            if item is None:
                return False, None
            expira_em, valor = item
            if self._relogio() >= expira_em:
                del self._dados[chave]
                return False, None
            return True, valor

    def limpar(self) -> None:
        with self._trava:
            self._dados.clear()