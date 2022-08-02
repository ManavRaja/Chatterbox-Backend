from fastapi import APIRouter, UploadFile, Depends, Header

from api.functions.auth import get_current_user
from api.models import User
from api.utils import get_settings, get_db, get_gridfs_db


user_settings_router = APIRouter()


@user_settings_router.post("/upload-pfp")
async def upload_profile_picture(pfp: UploadFile, gridfs_db=Depends(get_gridfs_db),
                                 current_user_info: User = Depends(get_current_user), csrf_token: str = Header(...)):
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
