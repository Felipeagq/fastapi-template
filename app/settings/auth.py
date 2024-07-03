from datetime import timedelta, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException

from starlette import status
from app.database.postgres.pg_core import SessionLocal
from app.models.user_model import Users
from app.database.postgres.pg_core import db_dependency
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from app.settings.config import configuration
from app.schemas.user_schema import CreateUserRequest, Token

from app.settings.security import get_current_user,create_access_token,bcrypt_context, authenticate_user

# Creamos el router de nuestra ruta de autenticación
router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# # Se crea el contexto de encriptación
# bcrypt_context = CryptContext(
#     schemes=["bcrypt"], 
#     deprecated="auto"
# )

# # Se especifica de donde va a obtener el token
# oauth2_bearer = OAuth2PasswordBearer(
#     tokenUrl="auth/token"
# )


# class CreateUserRequest(BaseModel):
#     username: str
#     password: str

# class Token(BaseModel):
#     access_token: str
#     token_type: str


# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()



################### FUNCIONES ###################

# Autenticación del usuario donde vemos si el usuario existe en base de datos 
# y la contraseña coindice
# def authenticate_user(username:str, password:str, db):
#     user = db.query(Users).filter(Users.username == username).first()
#     if not user:
#         return False
#     if not bcrypt_context.verify(password, user.hashed_password):
#         return False
#     return user


# def create_access_token(
#     username: str,
#     user_id:int,
#     expires_delta: timedelta
# ):
#     encode = {"sub":username, "id":user_id}
#     expires = datetime.utcnow() + expires_delta
#     encode.update({"exp":expires})
#     return jwt.encode(encode, configuration.SECRET_KEY, algorithm=configuration.ALGORITHM)


# async def get_current_user(token: Annotated[str,Depends(oauth2_bearer)]):
#     print(token)
#     try:
#         payload = jwt.decode(token,configuration.SECRET_KEY,algorithms=[configuration.ALGORITHM])
#         username: str = payload.get("sub")
#         user_id: int = payload.get("id")
#         if username is None or user_id is None:
#             raise HTTPException(status_code= status.HTTP_401_UNAUTHORIZED,detail="No se pudo validar usar usario, get_current_user")
#         return {"username":username,"id":user_id}
#     except JWTError:
#         raise HTTPException(status_code= status.HTTP_401_UNAUTHORIZED,detail="No se pudo validar usar usario, get_current_user exception")


################### RUTAS ###################

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(
    db: db_dependency,
    create_user_request: CreateUserRequest
):
    create_user_model = Users(
        username = create_user_request.username,
        hashed_password = bcrypt_context.hash(create_user_request.password)
    )
    db.add(create_user_model)
    db.commit()

    return {
        "msg":{
            "username": create_user_model.username,
            "password": create_user_model.hashed_password
        }
    }


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency
):
    user = authenticate_user(
        form_data.username, form_data.password, db
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se pudo validar el usuario"
        )
    token = create_access_token(user.username,user.id, timedelta(minutes=20))
    print(token)
    return {
        "access_token":token,
        "token_type": "bearer"
    }



