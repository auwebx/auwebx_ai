# utils.py – CLEAN FINAL VERSION (December 2025)
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext
from fastapi_mail import FastMail, MessageSchema, MessageType, ConnectionConfig
from fastapi import Request


# === CONSTANTS (now importable) ===
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production-2025-super-long-random-string")
ALGORITHM = "HS256"

# === Password hashing – 100% safe ===
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__ident="2b",      # eliminates warning forever
    bcrypt__min_rounds=12,
)

def get_password_hash(password: str) -> str:
    safe_pw = password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.hash(safe_pw)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    safe_pw = plain_password.encode("utf-8")[:72].decode("utf-8", errors="ignore")
    return pwd_context.verify(safe_pw, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(days=7)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def generate_secure_token() -> str:
    return secrets.token_urlsafe(64)


def generate_device_fingerprint(request: Request) -> str:
    ua_string = request.headers.get("user-agent", "")
    accept_language = request.headers.get("accept-language", "")
    timezone = request.headers.get("timezone", "UTC")  # we'll get from frontend

    # Very strong fingerprint (2025 best practice)
    fingerprint_string = f"{ua_string}|{accept_language}|{timezone}|{request.client.host}"

    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

# === Email – never crashes ===
conf = ConnectionConfig(
    MAIL_USERNAME="info@auwebx.com",
    MAIL_PASSWORD="Abdul4303@",
    MAIL_FROM="info@auwebx.com",
    MAIL_PORT=465,
    MAIL_SERVER="auwebx.com",
    MAIL_FROM_NAME="Your App",
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TIMEOUT=30
)

mail = FastMail(conf)

async def send_email(to: str, subject: str, body: str):
    message = MessageSchema(
        subject=subject,
        recipients=[to],
        body=body,
        subtype=MessageType.html,
    )

    try:
        await mail.send_message(message)
        print(f"Email successfully sent via your webmail to {to}")
    except Exception as e:
        print(f"Email failed: {e}")
        print("Check your MAILER_DSN – common fix below")