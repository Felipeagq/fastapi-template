from pydantic import BaseModel

class UserRequestSchema(BaseModel):
    username: str
    email: str
    password: str
    role: str

class UserResponseSchema(BaseModel):
    username: str
    email: str
    role: str  