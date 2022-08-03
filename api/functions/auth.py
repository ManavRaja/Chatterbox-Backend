from datetime import timedelta, datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import ssl
from typing import Optional

from fastapi import HTTPException, Depends
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from jose import jwt, JWSError
from passlib.context import CryptContext
from starlette import status
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED

from api import config
from api.models import UserInDB, TokenData
from api.utils import get_settings, get_db


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(
        self,
        token_url: str,
        scheme_name: str = None,
        scopes: dict = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(
            password={"tokenUrl": token_url, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.cookies.get("access_token")

        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None

        return param


oauth2_scheme = OAuth2PasswordBearerWithCookie(token_url="login")


async def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user(username: str, db):
    user_dict = await db.Users.find_one({"username": username})
    if user_dict:
        return UserInDB(**user_dict)


async def authenticate_user(username: str, password: str, db):
    user = await get_user(username, db)
    if not user:
        return False
    if not user.verified:
        return "User's email not verified."
    if not await verify_password(password, user.hashed_password):
        return False
    return user


async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    settings = get_settings()
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), settings: config.Settings = Depends(get_settings), db=Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWSError:
        raise credentials_exception
    user = await get_user(username=token_data.username, db=db)
    if user is None:
        raise credentials_exception
    return user


async def send_verification_email(user_email: str, username: str):
    """
    Sends email verification code to user's email address.
    :param user_email: str | email address of user which is where email verification code is sent
    :param username: str | username of user to address them by in email
    :return: nothing but sends email verification code to user's email address
    """
    settings = get_settings()

    port = 465
    sender_email_address = settings.GMAIL_ADDRESS
    password = settings.GMAIL_APP_PASSWORD
    api_domain = settings.API_DOMAIN
    verification_token = await create_access_token(data={"sub": user_email}, expires_delta=timedelta(minutes=480))

    message = MIMEMultipart()
    message["Subject"] = "Chatterbox Registration - Verify Email Address"
    message["From"] = sender_email_address
    message["To"] = user_email
    message_html = f"""
    Hello {username}!
    
    Welcome to Chatterbox. Below is your email verification code. It will only be valid for 8 hours.
        
    <br>
    <br>
        
    <strong>{verification_token}</strong>
    """
    message.attach(MIMEText(message_html, "html"))

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login(sender_email_address, password)
        server.sendmail(sender_email_address, user_email, message.as_string())
