# models.py
from sqlmodel import SQLModel, Field
from typing import Optional
from enum import Enum
from datetime import datetime


class Role(str, Enum):
    user = "user"
    moderator = "moderator"
    admin = "admin"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(unique=True, index=True)
    phone: Optional[str] = None
    state: Optional[str] = None
    hashed_password: str
    role: Role = Role.user
    is_active: bool = False
    email_verified_at: Optional[datetime] = None
    email_verification_token: Optional[str] = None
    password_reset_token: Optional[str] = None
    password_reset_expires_at: Optional[datetime] = None

    # ← NEW SECURITY FIELDS
    allowed_device_fingerprint: Optional[str] = None
    auth_version: int = 0                       # for logout all devices
    last_login_at: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    last_login_ua: Optional[str] = None         # User-Agent string