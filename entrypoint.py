# fastapi
from fastapi import FastAPI
from app.routes.user_manage import UserRouter
from app.routes.routes import ProtectedRouter

# database
from app.database.config import Base,engine

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(UserRouter)
app.include_router(ProtectedRouter)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('entrypoint:app', host='localhost', port=8000, reload=True)
