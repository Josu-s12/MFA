"""Flows y tasks de Prefect: cada paso de la verificación queda visible en la UI."""
import jwt
from prefect import flow, get_run_logger, task

from . import db, security
from .strategies import STRATEGIES


class ReplayAttackDetected(Exception):
    pass


class InvalidPreAuth(Exception):
    pass


class SecondFactorFailed(Exception):
    pass


class InvalidCredentials(Exception):
    pass


@task
def validate_pre_auth_state(pre_auth_token: str) -> int:
    logger = get_run_logger()
    try:
        claims = security.decode_token(pre_auth_token)
    except jwt.PyJWTError as e:
        raise InvalidPreAuth(f"pre_auth_token inválido o expirado: {e}")
    if claims.get("scope") != "pre_auth":
        raise InvalidPreAuth("El token no tiene scope pre_auth")
    user_id = int(claims["sub"])
    logger.info("pre_auth_token válido para user_id=%s", user_id)
    return user_id


@task
def check_anti_replay_cache(user_id: int, code: str) -> None:
    logger = get_run_logger()
    if security.replay_cache.seen(user_id, code):
        logger.error("REPLAY detectado: user_id=%s ya usó este código en los últimos 90 s", user_id)
        raise ReplayAttackDetected(f"El código ya fue usado por user_id={user_id} (ventana 90 s)")
    logger.info("Código no visto en caché anti-replay")


@task
def execute_mfa_strategy(user_id: int, code: str, method: str, activating: bool = False) -> str:
    logger = get_run_logger()
    strategy = STRATEGIES.get(method)
    if strategy is None:
        raise SecondFactorFailed(f"Método desconocido: {method}")
    logger.info("Ejecutando estrategia %s", type(strategy).__name__)
    result = strategy.verify(user_id, code)
    if not result.ok:
        logger.warning("Fallo 2FA: %s", result.detail)
        raise SecondFactorFailed(result.detail)
    logger.info("Éxito 2FA: %s", result.detail)   # <- aquí se ve C-1 / C / C+1
    if activating:
        db.set_mfa_state(user_id, db.ACTIVE)
        logger.info("Estado 2FA: PENDING_VERIFICATION -> ACTIVE")
    return result.detail


@task
def issue_elevated_session(user_id: int, code: str) -> str:
    logger = get_run_logger()
    security.replay_cache.mark(user_id, code)
    token = security.make_token(user_id, "access", security.ACCESS_TTL, mfa_verified=True)
    logger.info("Código marcado como usado; access_token emitido (mfa_verified=true)")
    return token


@flow(name="verify-2fa")
def verify_2fa_flow(pre_auth_token: str, code: str, method: str = "totp", activating: bool = False) -> str:
    user_id = validate_pre_auth_state(pre_auth_token)
    check_anti_replay_cache(user_id, code)
    execute_mfa_strategy(user_id, code, method, activating)
    return issue_elevated_session(user_id, code)


@task
def verify_password(username: str, password: str) -> int:
    logger = get_run_logger()
    row = db.get_user_by_name(username)
    if not row or not db.check_password(password, row["password_hash"]):
        logger.warning("Login fallido para '%s'", username)
        raise InvalidCredentials("Usuario o contraseña incorrectos")
    return row["id"]


@task
def issue_pre_auth_token(user_id: int) -> str:
    get_run_logger().info("pre_auth_token emitido (scope=pre_auth, 5 min)")
    return security.make_token(user_id, "pre_auth", security.PRE_AUTH_TTL)


@flow(name="login-step-1")
def login_flow(username: str, password: str) -> str:
    user_id = verify_password(username, password)
    return issue_pre_auth_token(user_id)
