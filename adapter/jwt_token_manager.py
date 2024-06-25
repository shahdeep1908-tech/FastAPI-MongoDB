from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from common.exceptions import HTTPException as CustomHTTPException
from jose import jwt
from config import app_config


class JWTAuthenticator:
    """
    The JWTAuthenticator class provides functionality for authenticating user requests by verifying JWT tokens in the
    Authorization header.
    """

    def __init__(self, ):
        self.ALGORITHM = app_config.JWT_ALGORITHM

    def create_token(self, payload: dict, secret_key: str, expires_delta: timedelta):
        """
        Create a JSON Web Token (JWT) based on the given payload, secret key, and expiration time delta.

        :param payload: A dictionary containing the data to be encoded in the JWT.
        :param secret_key: The secret key to be used for encoding the JWT.
        :param expires_delta: The time delta for when the JWT should expire.
        :return: A JSON Web Token (JWT) string.
        """
        payload["exp"] = datetime.now(timezone.utc) + expires_delta
        return jwt.encode(payload, secret_key,
                          algorithm=self.ALGORITHM, )

    def decode_token(self, token: str, secret_key: str):
        """
        Decode a JWT token and return its payload.

        :param token: The JWT token to be decoded.
        :param secret_key: The secret key used for encoding the token.
        :return: The payload contained in the token.
        :raises: jwt.exceptions.InvalidSignatureError: If the signature of the token is invalid
                 jwt.exceptions.DecodeError: If the token is invalid or expired.
        """
        payload = jwt.decode(token, secret_key, algorithms=[self.ALGORITHM])
        sub_data: str = payload.get("sub")
        if sub_data is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return sub_data

    def decode_invitation_token(self, token: str, secret_key: str):
        """
        Decode a JWT token and return its payload.

        :param token: The JWT token to be decoded.
        :param secret_key: The secret key used for encoding the token.
        :return: The payload contained in the token.
        :raises: jwt.exceptions.InvalidSignatureError: If the signature of the token is invalid
                 jwt.exceptions.DecodeError: If the token is invalid or expired.
        """
        try:
            payload = jwt.decode(token, secret_key, algorithms=[self.ALGORITHM])
            sub_data: str = payload.get("sub")
            workspace_data: str = payload.get("workspace_id")
            invited_by: str = payload.get("invited_by")
            if sub_data is None or workspace_data is None or invited_by is None:
                raise HTTPException(
                    status_code=status.HTTP_410_GONE,
                    detail="Could not validate credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return sub_data, workspace_data, invited_by
        except jwt.ExpiredSignatureError as e:
            raise CustomHTTPException("Invitation link expired")
        except jwt.JWTError as e:
            raise CustomHTTPException("Invitation link expired")

    def create_access_token(self, payload: dict):
        """
        Create a JWT access token.

        :param payload: A dictionary containing the payload data to be encoded in the JWT token.
        :return: A JWT access token.
        :raises: Exception: If an error occurs during the encoding process.
        """
        access_token_expires = timedelta(minutes=app_config.ACCESS_TOKEN_EXPIRE_MINUTES)
        return self.create_token(payload=payload, secret_key=app_config.ACCESS_TOKEN_SECRET_KEY,
                                 expires_delta=access_token_expires)

    def create_refresh_token(self, payload: dict):
        """
        Create and return a refresh token.

        :param payload: The data to be encoded and stored in the token.
        :return: The created refresh token.
        :raises: Exception: If an error occurs during the encoding process.
        """
        refresh_token_expires = timedelta(minutes=app_config.REFRESH_TOKEN_EXPIRE_MINUTES)
        return self.create_token(payload=payload, secret_key=app_config.REFRESH_TOKEN_SECRET_KEY,
                                 expires_delta=refresh_token_expires)
