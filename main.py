from fastapi import FastAPI, Depends
from starlette.requests import Request   # ← needed for Google OAuth

from auth import router as auth_router

# ← Fixed: imported ALL three dependencies
from deps import get_current_user, get_current_admin, get_moderator_or_admin

from database import create_db_and_tables
from models import User

app = FastAPI(title="FastAPI RBAC + Social Login + Password Reset 2025")

app.include_router(auth_router)

@app.on_event("startup")
def startup():
    create_db_and_tables()

# ← Fixed: removed duplicate "/" route – only one root endpoint
@app.get("/")
def root():
    return {"message": "RBAC + Google Login + Full Password Reset ready – go to /docs"}

@app.get("/users/me")
def me(user: User = Depends(get_current_user)):
    return user

@app.get("/admin-only")
def admin_route(user: User = Depends(get_current_admin)):
    return {"secret": "Only admins see this"}

@app.get("/moderator-or-admin")
def mod_route(user: User = Depends(get_moderator_or_admin)):
    return {"message": f"Welcome {user.role}"}