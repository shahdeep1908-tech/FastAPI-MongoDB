from typing import Any, Optional

from adapter.db_interface.db_interface_impl import DBInterface
from common import constants
from common.enums import Role
from depandencies import get_current_user, oauth2_scheme, get_current_user_from_refresh_token
from ebds.authentication.auth_model import Roles, User
from ebds.authentication.auth_schema import (UserRegistrationRequest,
                                             UserRegistrationResponse,
                                             UserLoginRequest, ForgotPasswordRequest, SetpasswordRequest,
                                             PasswordChangeRequest, UserLoginResponse,
                                             NewAccessTokenResponse, CommonResponse,
                                             LogoutRequest, UserProfileResponse, RoleListResponse)
from fastapi import APIRouter, status, Depends, Response, Form, File, UploadFile
from fastapi import BackgroundTasks
from ebds.authentication.auth_service import UserAuthentication

router = APIRouter()

_user_authentication = UserAuthentication()
role = Role()


@router.post("/api/add-roles",
             status_code=status.HTTP_201_CREATED,
             response_model=CommonResponse,
             include_in_schema=False, tags=["Roles | Permissions"])
async def api_create_roles(response: Response):
    return await(_user_authentication.create_roles(response, DBInterface(Roles)))


@router.get("/api/roles",
            status_code=status.HTTP_200_OK,
            response_model=RoleListResponse,
            summary=constants.ROLES_SUMMARY, tags=["Roles | Permissions"])
async def api_fetch_roles(response: Response):
    return await(_user_authentication.fetch_roles(response, DBInterface(Roles)))


@router.post("/api/register",
             status_code=status.HTTP_201_CREATED,
             response_model=UserRegistrationResponse,
             summary=constants.REGISTER_SUMMARY, tags=["Authentication"])
async def api_user_register(request: UserRegistrationRequest, response: Response):
    return await(_user_authentication.register(request, response, DBInterface(User)))


@router.post("/api/login",
             status_code=status.HTTP_200_OK,
             response_model=UserLoginResponse,
             summary=constants.LOGIN_SUMMARY, tags=["Authentication"])
async def api_user_login(request: UserLoginRequest, response: Response):
    return await(_user_authentication.login(request, response, DBInterface(User)))


@router.post('/api/user/refresh-token',
             status_code=status.HTTP_201_CREATED,
             response_model=NewAccessTokenResponse,
             summary=constants.NEW_ACCESS_TOKEN_SUMMARY, tags=["Authentication"])
async def api_refresh_token(response: Response, current_user: str = Depends(get_current_user_from_refresh_token)):
    return await(_user_authentication.create_new_access_token(response, current_user))


@router.patch("/api/user/change-password",
              status_code=status.HTTP_200_OK,
              response_model=CommonResponse,
              summary=constants.CHANGE_PASS_SUMMARY, tags=["Authentication"])
async def api_user_change_password(request: PasswordChangeRequest, response: Response,
                                   current_user: str = Depends(get_current_user)):
    return await(_user_authentication.change_password(request, response, DBInterface(User), current_user))


@router.post("/api/forgot-password",
             status_code=status.HTTP_200_OK,
             response_model=CommonResponse,
             summary=constants.FORGOT_PASS_SUMMARY, tags=["Authentication"])
async def api_user_forgot_password(request: ForgotPasswordRequest, response: Response,
                                   background_tasks: BackgroundTasks):
    return await(_user_authentication.forgot_password(request, response, DBInterface(User), background_tasks))


@router.patch("/api/password-reset-confirm",
              status_code=status.HTTP_200_OK,
              summary=constants.RESET_PASS_SUMMARY, tags=["Authentication"])
async def api_password_reset_confirm(request: SetpasswordRequest, reset_token: str, response: Response):
    return await(_user_authentication.password_reset_confirm(request, response, reset_token, DBInterface(User)))


@router.post("/api/user/logout",
             status_code=status.HTTP_200_OK,
             response_model=CommonResponse,
             summary=constants.LOGOUT_SUMMARY, tags=["Authentication"])
async def api_revoke_tokens(request: LogoutRequest, response: Response, token: str = Depends(oauth2_scheme)) -> Any:
    return await(_user_authentication.revoke_tokens(request, response, access_token=token))


@router.get("/api/user/get-user-profile",
            status_code=status.HTTP_200_OK,
            response_model=UserProfileResponse,
            summary=constants.GET_USER_PROFILE_SUMMARY, tags=["Users"])
async def get_user_profile(response: Response, current_user: str = Depends(get_current_user)):
    return await(_user_authentication.user_profile(response, DBInterface(User), current_user))


@router.patch("/api/user/update-profile",
              status_code=status.HTTP_200_OK,
              response_model=UserProfileResponse,
              summary=constants.CHANGE_PROFILE_SUMMARY, tags=["Users"])
async def update_profile(response: Response,
                         first_name: str = Form(..., min_length=1, max_length=50, pattern=r'^[a-zA-Z]+$'),
                         last_name: str = Form(..., min_length=1, max_length=50, pattern=r'^[a-zA-Z]+$'),
                         profile_image: Optional[UploadFile] = File(None),
                         current_user: str = Depends(get_current_user)):
    return await(_user_authentication.change_profile(response, first_name, last_name, profile_image, DBInterface(User),
                                                     current_user))
