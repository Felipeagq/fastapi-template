from pydantic import BaseModel
from typing import List

class UserCreate(BaseModel):
    username: str
    password: str
    roles: List[str] = []  # Lista de nombres de roles a asignar

class UserUsername(BaseModel):
    username: str