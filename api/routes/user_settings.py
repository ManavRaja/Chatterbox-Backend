from datetime import timedelta

from fastapi import APIRouter, UploadFile, Depends, Header, Form, HTTPException
from starlette.responses import Response

from api import config
from api.functions.auth import get_current_user, authenticate_user, create_access_token, verify_password, get_user, \
    get_password_hash
from api.models import User
from api.utils import get_settings, get_db, get_gridfs_db


user_settings_router = APIRouter()


@user_settings_router.post("/upload-pfp")
async def upload_profile_picture(pfp: UploadFile, gridfs_db=Depends(get_gridfs_db),
                                 current_user_info: User = Depends(get_current_user), csrf_token: str = Header(...)):  # skipcq: PYL-W0613, PYL-W0613
    """
    Route for a user to upload/update their profile picture. Takes in profile picture, creates AsyncIOMotorGridFSBucket
    object, gets the current user and requires csrf-token header to be present. Gets user's _id and sends query to
    gridfs to see if profile picture for that user already exists, if it does, it will delete that profile picture and
    add the new profile picture to gridfs. If there is no profile picture in gridfs for the user, it will add the
    profile picture tp gridfs.
    :param pfp: File in HTTP form body | the user's profile picture
    :param gridfs_db: AsyncIOMotorGridFSBucket object | used to query gridfs
    :param current_user_info: user's info structured in User model | used to make sure user is authenticated and which
    user is uploading profile picture
    :param csrf_token: HTTP header | prevents CSRF attack
    :return: 200 status code & that the user's profile picture has been set or updated
    :raises: 401 HTTPException if user isn't authenticated, 422 HTTPException if pfp or csrf_token aren't sent
    """
    user_id = current_user_info.id

    cursor = gridfs_db.find({"metadata.media_type": "profile_picture", "metadata.user_id": str(user_id)})
    while await cursor.fetch_next:  # This block of code runs if profile picture for user is already present
        grid_out = cursor.next_object()
        await gridfs_db.delete(grid_out._id)
        grid_in = gridfs_db.open_upload_stream(pfp.filename, metadata={"media_type": "profile_picture",
                                                                       "user_id": str(user_id)})
        await grid_in.write(pfp.file)
        await grid_in.close()
        return {"msg": f"Updated profile picture to be {pfp.filename}"}

    # Runs if profile picture for user isn't present
    grid_in = gridfs_db.open_upload_stream(str(user_id), metadata={"media_type": "profile_picture",
                                                                   "user_id": str(user_id)})
    await grid_in.write(pfp.file)
    await grid_in.close()
    return {"msg": f"{pfp.filename} successfully set as profile picture."}


@user_settings_router.post("/change-username")
async def change_username(response: Response, new_username: str = Form(..., max_length=25), password: str = Form(...),
                          current_user_info: User = Depends(get_current_user), csrf_token: str = Header(...),  # skipcq: PYL-W0613, PYL-W0613
                          db=Depends(get_db), settings: config.Settings = Depends(get_settings)):
    """
    Route for a user to change their username.
    :param response: Starlette object | to delete and set access_token cookie
    :param new_username: str in Form Body | the new username to be set
    :param password: str in Form Body | user's password for extra level of security
    :param current_user_info: user's info structured in User model |
    :param csrf_token: HTTP header | prevents CSRF attack
    :param db: AsyncIOMotorClient object | used to query db
    :param settings: object of Settings class | contains data from .env file to use for how long the access_token JWT
    should last
    :return: 200 status and that the user's username was changed
    :raises: 401 HTTPException if user isn't authenticated or password is incorrect, 422 HTTPException if new_username,
    password, or, 409 HTTPException if the user's new_username is already the current username, a user with that
    username already exists, or if csrf_token isn't set
    """

    """ Gets user's document from db for their hashed_password which is returned as UserInDB model as User model doesn't 
    contain a user's hashed_password """
    user = await get_user(current_user_info.username, db)

    if not await verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password.")
    elif new_username == current_user_info.username:
        raise HTTPException(status_code=409, detail="That's already your username.")
    elif await db.Users.find_one({"username": new_username}):
        raise HTTPException(status_code=409, detail="User with that username already exists.")

    """ Deletes access_token cookie and sets new one with the user's new username as old cookie wouldn't be valid as 
    the user's username will be changed and the old JWT was set with the previous username. ALso the new access_token 
    basically pushes the forced logout time of the user due to expired JWT back by settings.ACCESS_TOKEN_EXPIRE_MINUTES 
    instead of just the remainder of time they had from the old access_token. That's fine as the user had to retype 
    their password anyway. """
    response.delete_cookie(key="access_token")
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": new_username}, expires_delta=access_token_expires
    )
    response.set_cookie(
        key="access_token", value=f"Bearer {access_token}", secure=False, httponly=True, samesite="strict",
        max_age=604800)

    db.Users.update_one({"username": current_user_info.username}, {"$set": {"username": new_username}})
    return f"Changed your username to `{new_username}`."


@user_settings_router.post("/change-password")
async def change_password(current_password: str = Form(...), new_password: str = Form(...),
                          new_password_confirmation: str = Form(...), csrf_token: str = Header(...),  # skipcq: PYL-W0613, PYL-W0613
                          current_user_info: User = Depends(get_current_user), db=Depends(get_db)):
    """
    Route for a user to change their password.
    :param current_password:  str in Form Body | user's current password for extra level of security
    :param new_password: str in Form Body | password the user wants to change to
    :param new_password_confirmation: str in Form Body | user types in new_password again to make sure their new
    password is what they want it to be
    :param csrf_token: csrf_token: HTTP header | prevents CSRF attack
    :param current_user_info: user's info structured in User model | used to make sure user is authenticated and for
    API to know which user is changing their password
    :param db: AsyncIOMotorClient object | used to query db
    :return: 200 status and that the user's password was changed
    :raises: 401 HTTPException if user isn't authenticated or current_password is incorrect, 422 HTTPException if
    current_password, new_password, new_password_confirmation, of csrf-token header aren't set, 400 HTTP Exception if
    user's new password and password confirmation don't match and 409 HTTPException if user's new_password is already
    the current password
    """

    """ Gets user's document from db for their hashed_password which is returned as UserInDB model as User model doesn't 
    contain a user's hashed_password """
    user = await get_user(current_user_info.username, db)

    if not await verify_password(current_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect current password.")
    elif new_password != new_password_confirmation:
        raise HTTPException(status_code=400, detail="New password and new password confirmation don't match.")
    elif await verify_password(new_password, user.hashed_password):
        raise HTTPException(status_code=409, detail="That's already your password.")

    new_hashed_password = await get_password_hash(new_password)
    db.Users.update_one({"username": current_user_info.username}, {"$set": {"hashed_password": new_hashed_password}})
    return {"msg": "Your password was successfully changed."}


@user_settings_router.post("/change-fullname")
async def change_fullname(password: str = Form(...), new_fullname: str = Form(..., max_length=50), db=Depends(get_db),
                          current_user_info: User = Depends(get_current_user), csrf_token: str = Header(...),):  # skipcq: PYL-W0613, PYL-W0613
    """
    Route for a user to change their username.
    :param password: str in Form Body | user's password for extra level of security
    :param new_fullname: str in Form Body | the full name the user wants to change to
    :param db: AsyncIOMotorClient object | used to query db
    :param current_user_info:  user's info structured in User model | used to make sure user is authenticated and for
    API to know which user is changing their full name
    :param csrf_token: csrf_token: HTTP header | prevents CSRF attack
    :return: 200 status code & that the user's full name was changed
    :raises:  401 HTTPException if user isn't authenticated or if password is incorrect, 409 HTTPException if
    new_fullname is already their full name, 422 HTTPException if user didn't give new_fullname, password, or csrf-token
    """

    """ Gets user's document from db for their hashed_password which is returned as UserInDB model as User model doesn't 
    contain a user's hashed_password """
    user = await get_user(current_user_info.username, db)

    if not await verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password.")
    elif new_fullname == current_user_info.full_name:
        raise HTTPException(status_code=409, detail="That's already your full name.")

    db.User.update_one({"username": current_user_info}, {"$set": {"full_name": new_fullname}})
    return {"msg": f"Your full name was successfully changed to {new_fullname}."}
