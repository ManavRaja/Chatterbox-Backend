from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, Form, UploadFile

from api.functions.auth import get_current_user, HTTPException
from api.models import User
from api.utils import get_db, get_gridfs_db

chat_router = APIRouter()


@chat_router.post("/send-text-message")
async def send_message(current_user_info: User = Depends(get_current_user), csrf_token: str = Header(...),
                       receiver_username: str = Form(..., max_length=25), message: str = Form(..., max_length=1000),
                       db=Depends(get_db)):
    """
    Route for user to send text message to another user.
    :param current_user_info: user's info structured in User model | used to make sure user is authenticated and for
    API to know which user is sending the message
    :param csrf_token: HTTP header | prevents CSRF attack
    :param receiver_username: str of Form Body | the user that the message is being sent to
    :param message: str of Form Body | message to be sent to another user
    :param db: AsyncIOMotorClient object | used to query db
    :return: 200 code & that the message was sent to teh receiving user
    :raises: 422 HTTPException if any defined HTTP parameter is missing & 409 HTTPException if the receiving user
    doesn't exist or the receiving user's email isn't verified
    """
    receiver_username_document = await db.Users.find_one({"username": receiver_username})

    if receiver_username_document is None:
        raise HTTPException(status_code=409, detail="The receiving user doesn't exist.")
    elif not receiver_username_document["verified"]:
        raise HTTPException(status_code=409, detail="The receiving user's email isn't verified.")

    await db.Chat.insert_one({"timestamp": datetime.now(timezone.utc), "sender": current_user_info.username,
                              "receiver": receiver_username, "type": "text", "message": message, "read": False})
    return {"msg": f"Your message to {receiver_username} was successfully sent."}


@chat_router.post("/send-media")
async def send_message(media: UploadFile, current_user_info: User = Depends(get_current_user), csrf_token: str = Header(...),
                       receiver_username: str = Form(..., max_length=25), db=Depends(get_db),
                       gridfs_db=Depends(get_gridfs_db)):
    """
    Route for users to send media such as images or videos to other users.
    :param media: UploadFile object | the media being sent
    :param current_user_info: user's info structured in User model | used to make sure user is authenticated and for
    API to know which user is sending the media
    :param csrf_token: HTTP header | prevents CSRF attack
    :param receiver_username: str of Form Body | the user that the media is being sent to
    :param db: AsyncIOMotorClient object | used to query db
    :param gridfs_db: AsyncIOMotorGridFSBucket object | used to query gridfs
    :return: 200 code & that the media was sent to th receiving user
    :raises: 422 HTTPException if any defined HTTP parameter is missing & 409 HTTPException if the receiving user
    doesn't exist or the receiving user's email isn't verified
    """

    receiver_username_document = await db.Users.find_one({"username": receiver_username})

    if receiver_username_document is None:
        raise HTTPException(status_code=409, detail="The receiving user doesn't exist.")
    elif not receiver_username_document["verified"]:
        raise HTTPException(status_code=409, detail="The receiving user's email isn't verified.")

    grid_in = gridfs_db.open_upload_stream(media.filename, metadata={"media_type": f"chat_media_{media.content_type}",
                                                                     "timestamp": datetime.now(timezone.utc),
                                                                     "sender": current_user_info.username,
                                                                     "receiver": receiver_username,
                                                                     "read": False})
    await grid_in.write(media.file)
    await grid_in.close()
    return {"msg": f"Your media to {receiver_username} was successfully sent."}
