"""Strategy Pattern para el segundo factor."""
from abc import ABC, abstractmethod
from dataclasses import dataclass

from . import db, totp


@dataclass
class StrategyResult:
    ok: bool
    detail: str = ""


class SecondFactorStrategy(ABC):
    name: str

    @abstractmethod
    def verify(self, user_id: int, code: str) -> StrategyResult: ...


class TOTPStrategy(SecondFactorStrategy):
    name = "totp"

    def verify(self, user_id: int, code: str) -> StrategyResult:
        row = db.get_mfa(user_id)
        if not row:
            return StrategyResult(False, "2FA no configurado")
        offset = totp.verify_with_window(row["secret"], code)
        if offset is None:
            return StrategyResult(False, "Código TOTP inválido")
        label = {-1: "C-1 (reloj del celular ATRASADO)", 0: "C (reloj sincronizado)",
                 1: "C+1 (reloj del celular ADELANTADO)"}[offset]
        return StrategyResult(True, f"match en ventana {label}")


class BackupCodeStrategy(SecondFactorStrategy):
    name = "backup"

    def verify(self, user_id: int, code: str) -> StrategyResult:
        if not db.consume_backup_code(user_id, code.strip().lower()):
            return StrategyResult(False, "Código de respaldo inválido o ya usado")
        return StrategyResult(True, "código de respaldo consumido (un solo uso)")


STRATEGIES: dict[str, SecondFactorStrategy] = {s.name: s for s in (TOTPStrategy(), BackupCodeStrategy())}
