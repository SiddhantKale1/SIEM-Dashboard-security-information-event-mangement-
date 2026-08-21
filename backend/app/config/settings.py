from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    MONGODB_URI: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "siem_mvp"
    JWT_SECRET: str = "super_secret_jwt_key_change_me_in_production"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    HEARTBEAT_INTERVAL: int = 30
    METRIC_INTERVAL: int = 10
    NETWORK_CONTROLLER: str = "mock"
    USE_MOCK_DB: bool = True

    class Config:
        env_file = ".env"

settings = Settings()
