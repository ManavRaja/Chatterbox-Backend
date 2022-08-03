from datetime import timedelta

from fastapi import HTTPException, Depends, Header, Form, Cookie, APIRouter, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from starlette import status
from starlette.responses import Response

import api.config as config
from api.functions.auth import get_password_hash, authenticate_user, create_access_token, get_current_user, \
    send_verification_email
from api.models import User
from api.utils import get_settings, get_db


auth_router = APIRouter()


@auth_router.post("/login")
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), settings: config.Settings = Depends(get_settings), csrf_token: str = Header(...), db=Depends(get_db)): # skipcq: PYL-W0613
    user = await authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif user == "User's email not verified.":
        raise HTTPException(status_code=403, detail="User hasn't verified email.")
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    response.set_cookie(
        key="access_token", value=f"Bearer {access_token}", secure=False, httponly=True, samesite="strict", max_age=604800)
    return {"msg": "Successfully logged in."}


@auth_router.post("/register")
async def register(background_tasks: BackgroundTasks, csrf_token: str = Header(...), full_name: str = Form(..., max_length=50), username: str = Form(..., max_length=25), password: str = Form(...), email: str = Form(..., regex=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), db=Depends(get_db)):  # skipcq: PYL-W0613
    if await db.Users.find_one({"username": username}):
        raise HTTPException(status_code=409, detail="User with that username already exists.")
    hashed_password = await get_password_hash(password)
    await db.Users.insert_one({"full_name": full_name, "email": email, "username": username,
                               "hashed_password": hashed_password, "verified": False})
    background_tasks.add_task(send_verification_email, email, username)
    return {"msg": "Successfully registered! You must now verify your email before you can log in."}


@auth_router.post("/logout")
async def logout(response: Response, csrf_token: str = Header(...), access_token: str = Cookie(...)): # skipcq: PYL-W0613, PYL-W0613
    response.delete_cookie(key="access_token")
    return {"msg": "Successfully logged out!"}


@auth_router.get("/me", response_model=User)
async def current_user(current_user_info: User = Depends(get_current_user)):
    return current_user_info
