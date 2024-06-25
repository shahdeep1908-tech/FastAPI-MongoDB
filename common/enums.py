from enum import Enum

from pydantic import BaseModel


class Role(BaseModel):
    """
    An enumeration of the available modes for a user model.
    """
    OWNER: str = "OWNER"
    MEMBER: str = "MEMBER"
    DEVELOPER: str = "DEVELOPER"


class Permission(str, Enum):
    """
    An enumeration of the available permission for a workspace model.
    """
    DEFAULT: str = "DEFAULT"
    OPEN: str = "OPEN"
    CLOSED: str = "CLOSED"
    PRIVATE: str = "PRIVATE"
