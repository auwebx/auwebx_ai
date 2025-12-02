from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Literal, Optional
from datetime import datetime

class UserCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str = Field(..., min_length=2)
    email: EmailStr = Field(...)
    phone: str = Field(..., min_length=10)  # required for normal registration
    state: str = Field(...)                 # required for normal registration
    password: str = Field(..., min_length=8, max_length=72, description="Max 72 characters (bcrypt limit)")

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: EmailStr
    phone: Optional[str] = None      # ← FIXED: was str, now allows None (matches models.py + Google login)
    state: Optional[str] = None      # ← FIXED: was str, now allows None
    role: Literal["user", "moderator", "admin"]
    is_active: bool
    email_verified_at: Optional[datetime] = None

    # Optional: show device info in /users/me if you want
    last_login_at: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    last_login_ua: Optional[str] = None
    allowed_device_fingerprint: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"