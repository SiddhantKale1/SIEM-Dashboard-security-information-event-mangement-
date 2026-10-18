from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from datetime import timedelta, datetime, timezone
import logging

from app.auth.security import verify_password, create_access_token, decode_access_token, get_password_hash
from app.schemas.device import TokenResponse, UserResponse, ChangePasswordRequest
from app.database.connection import get_db
from app.config.settings import settings
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
logger = logging.getLogger(__name__)
# Use the same limiter instance attached to app.state
limiter = Limiter(key_func=get_remote_address)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    db = get_db()
    user = await db.users.find_one({"username": username})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return user

async def get_current_device(token: Annotated[str, Depends(oauth2_scheme)]):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        
    role = payload.get("role")
    if role != "device":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a device token")
        
    device_id = payload.get("sub")
    if not device_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
        
    db = get_db()
    device = await db.devices.find_one({"device_id": device_id})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
        
    if device.get("status") == "isolated":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device is isolated")
        
    return device

@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.LOGIN_RATE_LIMIT)
async def login(request: Request, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    db = get_db()
    
    # In a real system we'd have a seed script. For MVP, if no admin exists, create one on first login attempt if it matches a hardcoded default, or just always check the DB.
    user = await db.users.find_one({"username": form_data.username})
    
    # Seed admin if DB is empty for MVP simplicity
    if not user and form_data.username == "admin":
        count = await db.users.count_documents({})
        if count == 0:
            user = {
                "username": "admin",
                "password_hash": get_password_hash("admin"),
                "role": "admin",
                "must_change_password": True,   # Force change on first login
                "created_at": datetime.now(timezone.utc),
                "last_login": None
            }
            await db.users.insert_one(user)

    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # Update last login
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": datetime.now(timezone.utc)}}
    )
        
    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user.get("role")}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "role": current_user.get("role", "analyst"),
        "must_change_password": current_user.get("must_change_password", False),
    }

@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
):
    """Change the authenticated user's password."""
    if not verify_password(body.current_password, current_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    if len(body.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters",
        )
    db = get_db()
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {
            "password_hash": get_password_hash(body.new_password),
            "must_change_password": False,
        }}
    )
    logger.info(f"Password changed for {current_user['username']}")
    return {"detail": "Password updated successfully"}
