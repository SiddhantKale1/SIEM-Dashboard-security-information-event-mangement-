import os
import secrets
import logging
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

_SECRET_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "siem_data", ".jwt_secret"
)

def _load_or_create_jwt_secret() -> str:
    """Load the JWT secret from disk, generating a secure one if it doesn't exist."""
    os.makedirs(os.path.dirname(_SECRET_FILE), exist_ok=True)
    try:
        if os.path.exists(_SECRET_FILE):
            with open(_SECRET_FILE, "r") as f:
                secret = f.read().strip()
                if secret:
                    return secret
        # First run — generate and persist a strong secret
        secret = secrets.token_hex(64)
        with open(_SECRET_FILE, "w") as f:
            f.write(secret)
        logger.info("Generated new JWT secret and saved to siem_data/.jwt_secret")
        return secret
    except Exception as e:
        # Fallback: generate ephemeral secret (tokens won't survive restart)
        logger.critical(
            f"Could not persist JWT secret ({e}). Using ephemeral secret — "
            "all sessions will be invalidated on restart!"
        )
        return secrets.token_hex(64)

class Settings(BaseSettings):
    MONGODB_URI: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "siem_mvp"
    JWT_SECRET: str = ""           # Overridden below after class definition
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    HEARTBEAT_INTERVAL: int = 30
    METRIC_INTERVAL: int = 10
    NETWORK_CONTROLLER: str = "mock"
    USE_MOCK_DB: bool = True
    FRONTEND_ORIGIN: str = "http://localhost:5173"
    LOGIN_RATE_LIMIT: str = "200/minute"

    class Config:
        env_file = ".env"

settings = Settings()

# Override JWT_SECRET with persistent secure value (unless explicitly set via env)
if not os.environ.get("JWT_SECRET"):
    settings.JWT_SECRET = _load_or_create_jwt_secret()

