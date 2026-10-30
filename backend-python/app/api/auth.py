from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from datetime import timedelta, datetime, timezone
import logging

from app.auth.security import verify_password, create_access_token, decode_access_token, get_password_hash
from app.schemas.device import TokenResponse, UserResponse, ChangePasswordRequest, RegisterRequest
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
    
    # Seed admin if DB user does not exist
    if not user and form_data.username == "admin":
        admin_pass = os.getenv("ADMIN_PASSWORD") or os.urandom(8).hex()
        user = {
            "username": "admin",
            "password_hash": get_password_hash(admin_pass),
            "role": "admin",
            "must_change_password": False,
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
    update_filter = {"_id": user["_id"]} if "_id" in user else {"username": user["username"]}
    await db.users.update_one(
        update_filter,
        {"$set": {"last_login": datetime.now(timezone.utc)}}
    )
        
    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user.get("role")}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.LOGIN_RATE_LIMIT)
async def register(request: Request, body: RegisterRequest):
    clean_username = body.username.strip()
    if not clean_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username cannot be empty",
        )
    if len(clean_username) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be at least 3 characters",
        )
    if len(body.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters",
        )

    db = get_db()
    existing_user = await db.users.find_one({"username": clean_username})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{clean_username}' is already registered",
        )

    valid_roles = {"admin", "analyst", "viewer"}
    user_role = body.role.lower().strip() if body.role else "analyst"
    if user_role not in valid_roles:
        user_role = "analyst"

    new_user = {
        "username": clean_username,
        "password_hash": get_password_hash(body.password),
        "role": user_role,
        "must_change_password": False,
        "created_at": datetime.now(timezone.utc),
        "last_login": datetime.now(timezone.utc),
    }
    await db.users.insert_one(new_user)
    logger.info(f"New user registered: {clean_username} ({user_role})")

    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": clean_username, "role": user_role},
        expires_delta=access_token_expires,
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
