from dotenv import load_dotenv
from typing import Any, List, Optional, Union
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl
import os

load_dotenv()


class Config(BaseSettings):
    
    # PROJECT INFO
    PROJECT_NAME:str = "Big Study"
    PROJECT_VERSION:str = "v0.0.0"
    API_V1_STR:str = "/api/v1"

    # SECURITY UTILS
    SECRET_KEY: str = "5126402477d3baacae24c2be"
    # SECRET_KEY: str = os.getenv("SECRET_KEY") or os.urandom(12).hex()
    ACCESS_TOKEN_EXPIRE_MINUTES: int = os.getenv("TOKEN_EXPIRE_MINUTES") or 60
    ALGORITHM: str = "HS256"

    # POSTGRES DATABASE 
    _PG_NAME: str = os.getenv("PG_NAME") or None
    _PG_USER: str = os.getenv("PG_USER") or None
    _PG_PASSWORD: str = os.getenv("PG_PASSWORD") or None
    _PG_HOST: str = os.getenv("PG_HOST") or None
    _PG_PORT:str = os.getenv("PG_PORT") or None
    # POSTGRES DATABASE URL CONSTRUCTION
    SQLALCHEMY_DATABASE_URL: str = f"postgresql://{_PG_USER}:{_PG_PASSWORD}@{_PG_HOST}:{_PG_PORT}"
    print(SQLALCHEMY_DATABASE_URL)

    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []
    
    # STORAGE
    # STORAGE_PATH = os.path.join(os.getcwd(),"app","storage")


configuration = Config()