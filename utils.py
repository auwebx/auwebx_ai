# utils.py – RESEND WITHOUT DOMAIN VERIFICATION (WORKS IMMEDIATELY)
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext
from fastapi import Request
from user_agents import parse
import resend  # pip install resend

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production-2025-super-long-random-string")
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__ident="2b", bcrypt__min_rounds=12)

def get_password_hash(password: str) -> str:
    safe_pw = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.hash(safe_pw)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    safe_pw = plain_password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.verify(safe_pw, hashed_password)

def create_access_token(data: dict, user, expires_delta: timedelta = timedelta(days=7)):
    to_encode = data.copy()
    to_encode["ver"] = user.auth_version
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def generate_secure_token() -> str:
    return secrets.token_urlsafe(64)

def get_device_info(request: Request) -> dict:
    ua_string = request.headers.get("user-agent", "")
    user_agent = parse(ua_string)
    return {
        "browser": f"{user_agent.browser.family} {user_agent.browser.version_string}",
        "os": f"{user_agent.os.family} {user_agent.os.version_string}",
        "ip": request.client.host,
        "ua_string": ua_string,
    }

def generate_device_fingerprint(request: Request) -> str:
    info = get_device_info(request)
    accept_lang = request.headers.get("accept-language", "")
    timezone = request.headers.get("timezone", "UTC")
    fp_string = f"{info['ua_string']}|{info['ip']}|{accept_lang}|{timezone}"
    return hashlib.sha256(fp_string.encode()).hexdigest()

# === RESEND – NO DOMAIN VERIFICATION REQUIRED ===
resend.api_key = os.getenv("RESEND_API_KEY")

async def send_email(to: str, subject: str, body: str):
    if not resend.api_key:
        print("EMAIL PREVIEW (no Resend key):", to, subject, body)
        return

    try:
        resend.Emails.send({
            "from": "AUWebX <onboarding@resend.dev>",   # ← THIS WORKS WITHOUT ANY DOMAIN VERIFICATION
            "to": [to],
            "subject": subject,
            "html": body,
        })
        print(f"Email sent via Resend → {to}")
    except Exception as e:
        print(f"Resend failed: {e}")