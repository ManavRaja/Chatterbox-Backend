from fastapi import FastAPI

from api.routes.auth import auth_router


app = FastAPI()
app.include_router(auth_router, prefix="/auth")
