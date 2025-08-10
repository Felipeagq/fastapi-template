# fastapi
from fastapi import APIRouter,Depends

# database
from app.database.models import User

# utils
from app.utils.utils import require_roles

ProtectedRouter = APIRouter(prefix="/protected",tags=["protected"])



@ProtectedRouter.get("/protected/admin-area")
def admin_area(current_user: User = Depends(require_roles("admin"))):
    return {
        "msg": "Welcome to the admin area",
        "data":current_user
    }

@ProtectedRouter.get("/protected/admin-user-area")
def admin_user_area(current_user: User = Depends(require_roles("admin","user"))):
    return {
        "msg": "Welcome to the admin user area",
        "data":current_user
        }

@ProtectedRouter.get("/protected/user-area")
def user_area(current_user: User = Depends(require_roles("user"))):
    return {
        "msg": "Welcome to the user area",
        "data":current_user
        }