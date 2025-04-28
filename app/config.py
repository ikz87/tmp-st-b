import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load .env file explicitly if it exists
load_dotenv()

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/seniorthrive"

    # Auth0 Settings
    AUTH0_DOMAIN: str
    AUTH0_CLIENT_ID: str
    AUTH0_CLIENT_SECRET: str
    AUTH0_CALLBACK_URL: str = "http://localhost:8000/auth/callback" # Default, adjust if needed
    AUTH0_AUDIENCE: str # Often same as AUTH0_DOMAIN or a specific API identifier

    # Session Settings
    SESSION_SECRET_KEY: str # Generate a strong random key for this
    APP_BASE_URL: str = "http://localhost:3000" # URL of your frontend app

    ENVIRONMENT: str = "development"

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        # Allow reading directly from environment variables if .env is not found
        # or if variables are set directly in the environment
        extra = 'ignore'

settings = Settings()

# Basic validation
if not all([
    settings.AUTH0_DOMAIN,
    settings.AUTH0_CLIENT_ID,
    settings.AUTH0_CLIENT_SECRET,
    settings.SESSION_SECRET_KEY,
    settings.AUTH0_AUDIENCE
]):
    raise ValueError("Missing required Auth0 or Session configuration in environment variables or .env file")
