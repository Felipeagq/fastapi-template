from datetime import datetime, timedelta
from app.settings.config import configuration
from jose import jwt, JWTError
from app.models.user_model import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException
from typing import Annotated
from starlette import status

bcrypt_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto"
)



# Se especifica de donde va a obtener el token
oauth2_bearer = OAuth2PasswordBearer(
    tokenUrl="auth/token"
)


def create_access_token(
    username: str,
    user_id:int,
    expires_delta: timedelta
):
    encode = {"sub":username, "id":user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({"exp":expires})
    return jwt.encode(encode, configuration.SECRET_KEY, algorithm=configuration.ALGORITHM)


def authenticate_user(username:str, password:str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user

def create_access_token(
    username: str,
    user_id:int,
    expires_delta: timedelta
):
    encode = {"sub":username, "id":user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({"exp":expires})
    return jwt.encode(encode, configuration.SECRET_KEY, algorithm=configuration.ALGORITHM)


async def get_current_user(token: Annotated[str,Depends(oauth2_bearer)]):
    print(token)
    try:
        payload = jwt.decode(token,configuration.SECRET_KEY,algorithms=[configuration.ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if username is None or user_id is None:
            raise HTTPException(status_code= status.HTTP_401_UNAUTHORIZED,detail="No se pudo validar usar usario, get_current_user")
        return {"username":username,"id":user_id}
    except JWTError:
        raise HTTPException(status_code= status.HTTP_401_UNAUTHORIZED,detail="No se pudo validar usar usario, get_current_user exception")
    
    
    
user_dependency = Annotated[dict, Depends(get_current_user)]