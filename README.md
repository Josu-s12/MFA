# Taller 2FA TOTP desde cero + Prefect

```
/mobile-authenticator   App Expo (React Native): TOTP RFC 6238 calculado a mano (HMAC-SHA1 + truncamiento dinámico)
/backend-prefect        FastAPI + Prefect + SQLite: Step-Up Auth, Strategy, máquina de estados, anti-replay
```

## 1. Prefect server (terminal 1)
```bash
cd backend-prefect
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
prefect server start            # UI en http://127.0.0.1:4200
```

## 2. Backend (terminal 2)
```bash
cd backend-prefect
.venv\Scripts\activate
prefect config set PREFECT_API_URL=http://127.0.0.1:4200/api
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Login web: http://localhost:8000 · Docs: http://localhost:8000/docs

Pruebas automáticas: `python -m pytest tests` (vectores RFC 6238, PENDING→ACTIVE, replay, ventana C-1, backup codes).

## 3. App móvil (terminal 3)
```bash
cd mobile-authenticator
npm install
npx expo start                  # escanea con Expo Go
node totp.test.mjs              # vectores RFC 6238 (opcional)
```
En emulador sin cámara, pega la semilla Base32 que muestra la web.

## Flujo
1. `POST /auth/register` → `POST /auth/login` → `pre_auth_token` (scope `pre_auth`, solo sirve para 2FA).
2. Primera vez: `POST /auth/2fa/setup` (estado `PENDING_VERIFICATION`, devuelve QR) → `POST /auth/2fa/activate` con el primer código → `ACTIVE` + 8 códigos de respaldo.
3. Siguientes veces: `POST /auth/verify-2fa` `{code, method: "totp"|"backup"}` → `access_token` con `mfa_verified: true`.
4. `GET /api/boveda-secreta` solo acepta `access_token`.

Flow `verify-2fa` en Prefect: `validate_pre_auth_state` → `check_anti_replay_cache` → `execute_mfa_strategy` → `issue_elevated_session`.

## Guion de la demo
1. **Paridad**: escanea el QR con tu app y con Google/Microsoft Authenticator; mismos 6 dígitos.
2. **Modo avión**: activa modo avión en el celular, espera a que cambie la ventana, ingresa el código en la web (el PC sigue en red) y abre la bóveda.
3. **Replay**: reenvía el mismo código antes de 30 s → HTTP 409; en Prefect el flow queda *Failed* en `check_anti_replay_cache`.
4. **Clock skew / backup**: en los logs de `execute_mfa_strategy` se ve `match en ventana C-1 / C / C+1`; o usa un código de respaldo.
