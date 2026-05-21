import os
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    APP_NAME: str = "System Audit Platform"
    DEBUG: bool = False

    DATABASE_URL: str = "postgresql://audit_user:audit_pass_2024@db:5432/audit_db"

    SECRET_KEY: str = "change-this-to-a-random-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173", "http://localhost"]

    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"

    REPORTS_DIR: str = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports") if os.name == "nt" else "/app/reports"

    RATE_LIMIT: str = "30/minute"

    class Config:
        env_file = ".env"
        extra = "allow"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
