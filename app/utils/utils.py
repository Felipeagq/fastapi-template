# database
from app.database.config import Session,get_db
from app.database.models import User

# fastapi 
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer

#time
from datetime import datetime, timedelta

# jwt
import jwt


from passlib.context import CryptContext

SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)



def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_roles(*roles):
    def role_checker(user: User = Depends(get_current_user)):
        user_roles_names = [role.name for role in user.roles]
        if not any(r in user_roles_names for r in roles):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return user
    return role_checker

def require_action(action_name: str):
    def action_checker(user: User = Depends(get_current_user)):
        for role in user.roles:
            if any(action.name == action_name for action in role.actions):
                return user
        raise HTTPException(status_code=403, detail="Action not allowed")
    return action_checker