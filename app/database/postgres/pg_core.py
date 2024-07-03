from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import as_declarative, declared_attr, declarative_base
from app.settings.config import configuration
from typing import Any

SQLITE = "sqlite:///./solomon-dev.db"

engine = create_engine(
    SQLITE,
    connect_args={
        'check_same_thread':False
    }
)

SessionLocal = sessionmaker(
    autocommit = False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# @as_declarative()
# class Base:
#     id: Any
#     __name__: str
    
#     @declared_attr
#     def __tablename__(cls) -> str:
#         return cls.__tablename__.lower()