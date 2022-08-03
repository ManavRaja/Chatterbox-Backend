from pydantic import BaseSettings, AnyUrl


class Settings(BaseSettings):
    mongo_client_url: AnyUrl
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    GMAIL_ADDRESS: str
    GMAIL_APP_PASSWORD: str
    API_DOMAIN: AnyUrl

    class Config:
        env_file = "./.env"
