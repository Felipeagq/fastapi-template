from sqlalchemy import Column, String, Integer
from app.database.postgres.pg_core import Base

class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    hashed_password = Column(String)