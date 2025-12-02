# utils.py – FINAL FIXED VERSION (December 2025)
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext
from fastapi_mail import FastMail, MessageSchema, MessageType, ConnectionConfig
from fastapi import Request
from user_agents import parse  # pip install user-agents

import os
import resend

# === CONSTANTS ===
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production-2025-super-long-random-string")
ALGORITHM = "HS256"

# === Password hashing ===
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__ident="2b",
    bcrypt__min_rounds=12,
)

def get_password_hash(password: str) -> str:
    safe_pw = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.hash(safe_pw)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    safe_pw = plain_password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.verify(safe_pw, hashed_password)

# ← FIXED: correct syntax
def create_access_token(data: dict, user, expires_delta: timedelta = timedelta(days=7)):
    to_encode = data.copy()
    to_encode["ver"] = user.auth_version  # enables logout-all-devices
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def generate_secure_token() -> str:
    return secrets.token_urlsafe(64)

# === Device info & fingerprint ===
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

# === Email – your own webmail (working perfectly) ===
# conf = ConnectionConfig(
#     MAIL_USERNAME="info@auwebx.com",
#     MAIL_PASSWORD="Abdul4303@",
#     MAIL_FROM="info@auwebx.com",
#     MAIL_PORT=465,
#     MAIL_SERVER="mail.auwebx.com",
#     MAIL_FROM_NAME="AUWEBx AI",
#     MAIL_STARTTLS=False,
#     MAIL_SSL_TLS=True,
#     USE_CREDENTIALS=True,
#     VALIDATE_CERTS=False,            # critical for shared hosting
#     TIMEOUT=30
# )

# Load API key from environment
resend.api_key = os.getenv("RESEND_API_KEY")



async def send_email(to: str, subject: str, html: str):
    """
    Sends an email using Resend API.
    Works on Render without SMTP or port issues.
    """
    try:
        response = resend.Emails.send({
            "from": "AUWEBx <info@auwebx.com>",   # Your domain email
            "to": [to],
            "subject": subject,
            "html": html
        })

        print("Email sent:", response)
        return True

    except Exception as e:
        print("Resend Error:", e)
        return False

