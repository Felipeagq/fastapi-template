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


class CreateUserRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str