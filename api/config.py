from pydantic import BaseSettings, AnyUrl


class Settings(BaseSettings):
    mongo_client_url: AnyUrl
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    class Config:
        env_file = "./.env"
