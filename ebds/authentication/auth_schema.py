from typing import Union, Optional, List, Dict

from pydantic import BaseModel, EmailStr, Field, conint, field_validator

from common.enums import Role


class PageParams(BaseModel):
    """ Request query params for paginated API. """
    page: conint(ge=1) = 1
    size: conint(ge=1, le=100) = 10


class ResponseMessage(BaseModel):
    status: Optional[int] = None
    message: str


class ErrorMessage(BaseModel):
    message: Union[Dict[str, List[str]], None]


class UserRegistrationRequest(BaseModel):
    """
    Request schema for user registration.
    """
    first_name: str = Field(min_length=1, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    password: str
    email: EmailStr

    @field_validator("email")
    def email_lowercase(cls, v):
        return v.lower()

    @field_validator("first_name", "last_name")
    def name_must_be_alpha(cls, v, field):
        if not v.isalpha():
            raise ValueError(
                f"{field.field_name.replace('_', ' ').capitalize()} must contain only alphabetic characters")
        return v

    class Config:
        """
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        extra = "forbid"


class UserOrganizationResponseData(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    role_id: Optional[Union[Role, str]] = None


class UserRoleResponseData(BaseModel):
    id: str
    name: str


class RoleListResponse(BaseModel):
    results: Union[Dict[str, Union[List[UserRoleResponseData], None]], None]
    errors: Union[ErrorMessage, None]


class UserData(BaseModel):
    id: str
    first_name: str
    last_name: str
    email: str
    profile_image: Optional[str]
    is_verified: bool
    is_active: Optional[bool] = False
    role: UserRoleResponseData


class UserRegistrationResponseData(BaseModel):
    """
    Response schema for user registration.
    """
    user: UserData

    class Config:
        """
        from_attributes: This is  used to convert back database object into json datatypes.
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        from_attributes = True


class UserRegistrationResponse(ResponseMessage):
    results: Union[Dict[str, Union[UserRegistrationResponseData, None]], None]
    errors: Union[ErrorMessage, None]


class VerifyEmailUserData(BaseModel):
    id: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    profile_image: Optional[str] = None
    is_verified: Optional[bool] = None
    is_active: Optional[bool] = None
    role: Optional[UserRoleResponseData] = None

    class Config:
        """
        from_attributes: This is  used to convert back database object into json datatypes.
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        from_attributes = True


class VerifyEmailTokenResponseData(BaseModel):
    access: Optional[str] = None
    refresh: Optional[str] = None


class PermissionData(BaseModel):
    id: str
    name: str


class NamespaceData(BaseModel):
    id: str
    name: str


class WorkspacesData(BaseModel):
    id: str
    name: str
    description: str
    permission: PermissionData
    namespace: NamespaceData


class VerifyEmailResponseData(BaseModel):
    """
    Response schema for user login.
    """
    token: VerifyEmailTokenResponseData
    user: VerifyEmailUserData
    is_new_user: bool
    success: bool


class VerifyEmailResponse(ResponseMessage):
    results: Union[Dict[str, Union[VerifyEmailResponseData, None]], None]
    errors: Union[ErrorMessage, None]


class MembersData(BaseModel):
    id: str
    user: UserData


class InviteMemberWorkspaceDetail(BaseModel):
    """
    Response schema for user login.
    """
    workspace: WorkspacesData
    invited_by: UserData
    members: List[MembersData] = []
    members_count: int

    class Config:
        """
        from_attributes: This is  used to convert back database object into json datatypes.
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        from_attributes = True


class InviteMemberWorkspaceDetailResponse(ResponseMessage):
    results: Union[Dict[str, Union[InviteMemberWorkspaceDetail, None]], None]
    errors: Union[ErrorMessage, None]


class UserLoginRequest(BaseModel):
    """
    Request schema for user login.
    """
    email: EmailStr
    password: str

    @field_validator("email")
    def email_lowercase(cls, v):
        return v.lower()

    class Config:
        """
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        extra = "forbid"
        json_schema_extra = {
            "examples": [
                {
                    "email": "john.doe@example.com",
                    "password": "Cre$dCqM3Lixqt"
                }
            ]
        }


class TokenResponseData(BaseModel):
    access: str
    refresh: str


class UserLoginResponseData(BaseModel):
    """
    Response schema for user login.
    """
    token: TokenResponseData
    user: UserData


class UserLoginResponse(ResponseMessage):
    results: Union[Dict[str, Union[UserLoginResponseData, None]], None]
    errors: Union[ErrorMessage, None]


class NewAccessTokenResponseData(BaseModel):
    token: TokenResponseData


class NewAccessTokenResponse(ResponseMessage):
    results: Union[Dict[str, Union[NewAccessTokenResponseData, None]], None]
    errors: Union[ErrorMessage, None]

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "status": 201,
                    "message": "New token created successfully",
                    "results": {
                        "data": {
                            "token": {
                                "access": "access_1234",
                                "refresh": "refresh_1234"
                            }
                        }
                    },
                    "errors": {
                        "message": {}
                    }
                }
            ]
        }


class ForgotPasswordRequest(BaseModel):
    """
    Request schema for user forgot password.
    """
    email: EmailStr

    @field_validator("email")
    def email_lowercase(cls, v):
        return v.lower()

    class Config:
        """
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        extra = "forbid"
        json_schema_extra = {
            "examples": [
                {
                    "email": "john.doe@example.com"
                }
            ]
        }


class SetpasswordRequest(BaseModel):
    """
    Request schema for user reset password.
    """
    new_password: str

    class Config:
        """
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        extra = "forbid"
        json_schema_extra = {
            "examples": [
                {
                    "new_password": "!Y6zIjftaa9OPe"
                }
            ]
        }


class PasswordChangeRequest(BaseModel):
    """
    Request schema for user change password.
    """
    old_password: str
    new_password: str

    class Config:
        """
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        extra = "forbid"
        json_schema_extra = {
            "examples": [
                {
                    "old_password": "Cre$dCqM3Lixqt",
                    "new_password": "!Y6zIjftaa9OPe"
                }
            ]
        }


class CommonResponse(ResponseMessage):
    results: Union[Dict[str, None], None]
    errors: Union[ErrorMessage, None]

    class Config:
        """
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        extra = "forbid"
        json_schema_extra = {
            "examples": [
                {
                    "status": 200,
                    "message": "Common message schema w/o data",
                    "results": {
                        "data": None
                    },
                    "errors": {
                        "message": {}
                    }
                }
            ]
        }


class LogoutRequest(BaseModel):
    refresh_token: str

    class Config:
        """
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        extra = "forbid"
        json_schema_extra = {
            "examples": [
                {
                    "refresh_token": "refresh_token_1234"
                }
            ]
        }


class UserProfileResponse(ResponseMessage):
    results: Union[Dict[str, Union[UserRegistrationResponseData, None]], None]
    errors: Union[ErrorMessage, None]

    class Config:
        """
        forbid: This is used to validation fail, if extra attribute is passed rather than defined above.
        """
        extra = "forbid"
