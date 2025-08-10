# fastapi
from fastapi import APIRouter, Depends,HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Database
from app.database.models import User,Role
from app.database.config import Session, get_db

# utils
from app.utils.utils import (
    require_action,require_roles, 
    create_access_token, verify_password,get_current_user,
    get_password_hash
)

# schemas
from app.schema.schemas import UserCreate, UserUsername


UserRouter = APIRouter(prefix="/users", tags=["Users"])


@UserRouter.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@UserRouter.get("/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "roles": [r.name for r in current_user.roles]}

@UserRouter.delete("/")
def delete_user_by_username(user_data:UserUsername,user = Depends(require_roles("admin")), db:Session = Depends(get_db)):
    user = db.query(User).filter(User.username ==user_data.username).first()
    if user:
        db.delete(user)
        db.commit()
        return {
            "data":f"Usuario eliminado correctamente {user_data.username}",
            "user": user
        }
    return {
        "data": f"No hay usuario con el username {user_data.username}"
    }

@UserRouter.put("/me")
def update_user_by_username():
    pass

@UserRouter.post("/users")
def create_user(user_data: UserCreate, db: Session = Depends(get_db)):
    # Verificar si el usuario ya existe
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    # Hashear contraseña
    hashed_password = get_password_hash(user_data.password)
    # Crear instancia de usuario
    new_user = User(username=user_data.username, hashed_password=hashed_password)
    # Asignar roles si existen
    if user_data.roles:
        roles_in_db = db.query(Role).filter(Role.name.in_(user_data.roles)).all()
        if len(roles_in_db) != len(user_data.roles):
            raise HTTPException(status_code=400, detail="One or more roles do not exist")
        new_user.roles = roles_in_db
    # Guardar en base de datos
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {
        "id": new_user.id,
        "username": new_user.username,
        "roles": [role.name for role in new_user.roles]
    }

@UserRouter.get("/list")
def users_lists(db:Session = Depends(get_db), user = Depends(require_roles("admin"))):
    return db.query(User).all()

