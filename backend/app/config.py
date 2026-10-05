from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings

# Resolve paths relative to this config file:
# backend/app/config.py -> parent is app -> parent is backend
APP_DIR = Path(__file__).resolve().parent
BASE_DIR = APP_DIR.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "trained_models"

class Settings(BaseSettings):
    PROJECT_NAME: str = "SOCPilot: Autonomous Security Alert Investigation Agent"
    VERSION: str = "2.0.0"
    
    # Path configurations
    BASE_DIR: Path = BASE_DIR
    DATA_DIR: Path = DATA_DIR
    MODEL_DIR: Path = MODEL_DIR
    DATASET_PATH: Path = DATA_DIR / "GUIDE_Train.csv"
    THREAT_INTEL_PATH: Path = DATA_DIR / "threat_intel.json"
    
    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'socpilot.db'}"
    
    # External integrations (optional)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    API_BASE_URL: str = "http://127.0.0.1:8000"
    
    # Server configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
