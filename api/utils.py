from functools import lru_cache

import motor.motor_asyncio

from . import config


@lru_cache
def get_settings():
    return config.Settings()


async def get_db():
    settings = get_settings()
    return motor.motor_asyncio.AsyncIOMotorClient(settings.mongo_client_url)["Chatterbox"]


async def get_gridfs_db():
    return motor.motor_asyncio.AsyncIOMotorGridFSBucket(await get_db())
