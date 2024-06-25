from fastapi import Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from adapter.db_interface.db_interface_impl import DBInterface

from config import app_config
from adapter.jwt_token_manager import JWTAuthenticator
from ebds.authentication.auth_model import BlackListTokens

jwt_authentication = JWTAuthenticator()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="login",
    scopes={"me": "Read information about the current user."},
)


async def decode_current_user_token(token: str, secret_key: str):
    """
    The function is used to retrieve the current user information based on the provided access token.
    It is a dependency for the FastAPI route functions that require authentication.

    :param token: The access token passed in the request's authorization header.
    :param secret_key: The type of secret key to be used for decoding.
    :return: A dictionary containing the user information such as the user ID, username, email, etc.
    """
    black_list_token_interface = DBInterface(BlackListTokens)
    if await black_list_token_interface.get_single_item_by_filters({"token": token}):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid token")
    try:
        return jwt_authentication.decode_token(token=token, secret_key=secret_key)
    except JWTError as err:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    The get_current_user function is used to retrieve the current user information based on the provided access token.
    It is a dependency for the FastAPI route functions that require authentication.

    :param token: The access token passed in the request's authorization header.
    :return: A dictionary containing the user information such as the user ID, username, email, etc.
    """
    return await decode_current_user_token(token, app_config.ACCESS_TOKEN_SECRET_KEY)


async def get_current_user_from_refresh_token(token: str = Depends(oauth2_scheme)):
    """
    This function is used to get the current user information from a refresh token.

    :param token: The refresh token to decode and extract the user information from.
    :return: A dictionary containing the new_access_token obtained from the refresh token.
    """
    return await decode_current_user_token(token, app_config.REFRESH_TOKEN_SECRET_KEY)
