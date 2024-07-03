from fastapi import FastAPI, HTTPException
import uvicorn
# import app.models.user_model as models
from app.models.user_model import Base
from app.database.postgres.pg_core import SessionLocal, engine
from app.settings.auth import router as auth_router
from app.database.postgres.pg_core import db_dependency
from app.settings.security import user_dependency

app = FastAPI(
    title="Solomon Backend",
    version="v0.0.1"
)

app.include_router(auth_router)

try:
    Base.metadata.create_all(bind=engine)
except:
    print("No se pudo")

@app.get("/")
def entrypoint():
    return {
        "title":app.title,
        "version": app.version
    }

@app.get("/secure")
async def user(user:user_dependency, db:db_dependency):
    if user is None:
        raise HTTPException(status_code="401",detail="Autenticación fallida")
    return {
        "User":user
    }
    

if __name__ == "__main__":
    uvicorn.run(
        "entrypoint:app",
        host="localhost",
        port=8080,
        reload=True
    )