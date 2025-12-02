from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select
from datetime import datetime, timedelta
from database import get_session
from deps import get_current_user
from models import User
from schemas import UserCreate, UserOut, Token
from utils import (
    get_password_hash, verify_password, create_access_token,
    generate_secure_token, send_email, generate_device_fingerprint, get_device_info
)
from oauth import oauth
from starlette.responses import RedirectResponse
import os

router = APIRouter(prefix="/auth", tags=["auth"])

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")

# === Normal Registration ===
@router.post("/register", response_model=UserOut)
async def register(user_data: UserCreate, background_tasks: BackgroundTasks, session=Depends(get_session)):
    if session.exec(select(User).where(User.email == user_data.email)).first():
        raise HTTPException(400, "Email already registered")

    hashed = get_password_hash(user_data.password)
    token = generate_secure_token()

    new_user = User(
        name=user_data.name,
        email=user_data.email,
        phone=user_data.phone,
        state=user_data.state,
        hashed_password=hashed,
        email_verification_token=token
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    verify_url = f"{BASE_URL}/auth/verify-email?token={token}"
    await send_email(
        user_data.email,
        "Verify your email",
        f"<h2>Welcome {user_data.name}!</h2><p>Click <a href='{verify_url}'>Click here to verify your email</a></p>"
    )

    return new_user

# === Email Verification ===
@router.get("/verify-email")
async def verify_email(token: str, session=Depends(get_session)):
    user = session.exec(select(User).where(User.email_verification_token == token)).first()
    if not user:
        raise HTTPException(400, "Invalid or expired token")

    user.is_active = True
    user.email_verified_at = datetime.utcnow()
    user.email_verification_token = None
    session.add(user)
    session.commit()

    return {"message": "Email verified! You can now log in."}

# === Normal Login ===
@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    session=Depends(get_session)
):
    user = session.exec(select(User).where(User.email == form.username)).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Please verify your email first")

    # Device fingerprint
    fingerprint = generate_device_fingerprint(request)
    device_info = get_device_info(request)

    # Update last login info
    user.last_login_at = datetime.utcnow()
    user.last_login_ip = device_info["ip"]
    user.last_login_ua = device_info["ua_string"]

    # Device binding logic
    if user.allowed_device_fingerprint is None:
        user.allowed_device_fingerprint = fingerprint
        print(f"New device registered for {user.email}")

    elif user.allowed_device_fingerprint != fingerprint:
        raise HTTPException(
            status_code=403,
            detail="Access denied: This account is locked to one device only. Contact admin to switch device."
        )

    session.add(user)
    session.commit()

    token = create_access_token(
        {"sub": str(user.id), "role": user.role},
        user
    )

    return {"access_token": token}


# === FORGET PASSWORD (full) ===
@router.post("/forget-password")
async def forget_password(email: str, background_tasks: BackgroundTasks, session=Depends(get_session)):
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        return {"message": "If the email exists, a reset link has been sent"}  # security best practice

    token = generate_secure_token()
    expires = datetime.utcnow() + timedelta(hours=1)

    user.password_reset_token = token
    user.password_reset_expires_at = expires
    session.add(user)
    session.commit()

    reset_url = f"{BASE_URL}/auth/reset-password?token={token}"

    await send_email(
        email,
        "Password Reset Request",
        f"<p>Click the link below to reset your password (expires in 1 hour):</p>"
        f"<a href='{reset_url}'>{reset_url}</a>"
    )

    return {"message": "If the email exists, a reset link has been sent"}

# === RESET PASSWORD (full) ===

@router.get("/reset-password")
async def auto_reset_password(
    token: str,
    new_password: str,   # ← user types it in the browser URL or you send in email
    session=Depends(get_session)
):
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = session.exec(select(User).where(User.password_reset_token == token)).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    if user.password_reset_expires_at and user.password_reset_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Reset token has expired")

    user.hashed_password = get_password_hash(new_password)
    user.password_reset_token = None
    user.password_reset_expires_at = None
    session.add(user)
    session.commit()

    return {"message": "Password reset successful! You can now log in."}

# === GOOGLE SOCIAL LOGIN ===
@router.get("/login/google")
async def login_google(request: Request):
    redirect_uri = f"{BASE_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/google/callback")
async def google_callback(request: Request, session=Depends(get_session)):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = await oauth.google.parse_id_token(request, token)
    except Exception as e:
        raise HTTPException(400, "Google authentication failed")

    email = user_info["email"]
    name = user_info.get("name", email.split("@")[0])
    picture = user_info.get("picture")

    user = session.exec(select(User).where(User.email == email)).first()

    if not user:
        user = User(
            name=name,
            email=email,
            phone=None,
            state=None,
            hashed_password="google-social-login",  # marker
            is_active=True,
            email_verified_at=datetime.utcnow(),
            role="user"
        )
        session.add(user)
        session.commit()
        session.refresh(user)

    access_token = create_access_token({"sub": str(user.id), "role": user.role})

    # For API use – return token. For frontend, you would redirect with token in query/fragment
    return {"access_token": access_token, "token_type": "bearer", "user": user.name}

# Normal logout – just frontend clears token (optional backend endpoint)
@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out successfully (token cleared on client)"}

# LOGOUT FROM ALL DEVICES (user can do it from profile)
@router.post("/logout-all-devices")
async def logout_all_devices(
    current_user: User = Depends(get_current_user),
    session=Depends(get_session)
):
    current_user.auth_version += 1
    session.add(current_user)
    session.commit()
    return {"message": "Successfully logged out from ALL devices"}