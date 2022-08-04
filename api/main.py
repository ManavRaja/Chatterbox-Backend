from fastapi import FastAPI

from api.routes.auth import auth_router
from api.routes.user_settings import user_settings_router


app = FastAPI()
app.include_router(auth_router, prefix="/auth")
app.include_router(user_settings_router, prefix="/settings")
