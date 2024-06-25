import uuid
from datetime import timedelta

from typing import Optional

from fastapi import status, BackgroundTasks, UploadFile
from fastapi_mail import MessageSchema
from jose import JWTError
from sqlalchemy.exc import SQLAlchemyError

from adapter.db_interface.db_interface_impl import DBInterface
from adapter.jwt_token_manager import JWTAuthenticator
from app_loggers import app_logger
from common import messages
from common.enums import Role
from common.utils import convert_data_into_json
from adapter.hashing import Hasher
from adapter.app_mail import AppMail
from config import app_config
from common.exceptions import BadRequestException, HTTPException, ForbiddenException, TokenExpiryException
from ebds.authentication.auth_model import Roles, BlackListTokens, User
from ebds.authentication.auth_schema import UserRegistrationRequest, UserLoginRequest, PasswordChangeRequest, \
    ForgotPasswordRequest, SetpasswordRequest

from ebds.authentication.auth_schema_validation import password_validation
from ebds.workspace.workspace_model import WorkSpaceInviteMember, UserWorkSpace

_hasher = Hasher()
jwt_authentication = JWTAuthenticator()
_app_mail = AppMail()
role = Role()


class UserAuthentication:
    @staticmethod
    async def create_roles(response, db_interface: DBInterface) -> dict:
        data, message, errors = None, "", {}
        try:
            roles = role.dict()
            existing_roles = await db_interface.read_all()
            existing_roles_lst = [item["name"] for item in existing_roles]
            for role_name in roles.values():
                if role_name in existing_roles_lst:
                    continue
                _ = await db_interface.create_with_uuid(data={"name": role_name})

            message = messages.ROLES_SUCCESS.format("created")
            response.status_code = status.HTTP_201_CREATED
            app_logger.info("Role created successfully")
        except SQLAlchemyError as err:
            errors[type(err).__name__] = [str(err)]
            message = str(err)
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            app_logger.error(f"SQLAlchemyError ::: Error while creating role ::: {message}")
        except Exception as err:
            errors[type(err).__name__] = [str(err)]
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error while creating role ::: {message}")
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def fetch_roles(response, db_interface: DBInterface) -> dict:
        data, message, errors = None, "", {}
        try:
            data = await db_interface.read_all()
            message = messages.ROLES_SUCCESS.format("fetched")
            response.status_code = status.HTTP_200_OK
            app_logger.info("Role fetched successfully")
        except SQLAlchemyError as err:
            errors[type(err).__name__] = [str(err)]
            message = str(err)
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            app_logger.error(f"SQLAlchemyError ::: Error while fetching role ::: {message}")
        except Exception as err:
            errors[type(err).__name__] = [str(err)]
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error while fetching role ::: {message}")
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def register(request: UserRegistrationRequest, response, db_interface: DBInterface) -> dict:
        data, message, errors = None, "", {}
        try:
            # Instantiate DB interfaces
            role_db_interface = DBInterface(Roles)
            workspace_invite_member_db_interface = DBInterface(WorkSpaceInviteMember)

            # Convert request data to JSON
            request_data = convert_data_into_json(request)

            # Check if user with the same email already exists
            email_filter_list = {"email": request_data.get("email")}
            if _ := await db_interface.get_single_item_by_filters(email_filter_list):
                errors["email"] = [messages.ERR_MSG_ALREADY_EXIST]
                raise BadRequestException(messages.ERR_MSG_ALREADY_EXIST)

            if not password_validation(request_data.get("password")):
                errors["password"] = [messages.ERR_PASSWORD_WRONG]
                raise HTTPException(messages.ERR_PASSWORD_WRONG)

            # Hash the password
            request_data["password"] = _hasher.get_password_hash(request_data["password"])
            request_data["is_verified"] = True
            request_data["is_active"] = True
            request_data["is_deleted"] = False
            request_data["profile_image"] = f"{app_config.APP_URL}/uploads/default.png"

            # Check user for any invitation in any workspace
            invite_member_obj = await workspace_invite_member_db_interface.get_single_item_by_filters(
                {'email': request_data["email"], 'is_accepted': False})

            # Check and Fetch role objects
            role_obj = await role_db_interface.get_single_item_by_filters({"name": role.OWNER})
            if not role_obj:
                errors["role_id"] = [messages.ROLE_NOT_FOUND]
                raise BadRequestException(messages.ROLE_NOT_FOUND)
            request_data["role_id"] = invite_member_obj['role_id'] if invite_member_obj else role_obj['id']

            user_data = await db_interface.create_with_uuid(data=request_data)
            user_role_obj = await role_db_interface.get_single_item_by_filters({"id": user_data['role_id']})
            user_data['role'] = user_role_obj

            if invite_member_obj:
                user_workspace_db_interface = DBInterface(UserWorkSpace)
                user_workspace_request_data = {"user_id": user_data['id'],
                                               "workspace_id": invite_member_obj['workspace_id'],
                                               "role_id": invite_member_obj['role_id']}
                _ = await workspace_invite_member_db_interface.update(id=invite_member_obj['id'],
                                                                      data={"is_accepted": True})
                user_workspace_obj = await user_workspace_db_interface.create_with_uuid(
                    data=user_workspace_request_data)
                app_logger.info(
                    f"User registered through invitation ::: Workspace-{user_workspace_obj['workspace_id']}")

            data = {"user": convert_data_into_json(user_data)}

            message = messages.REGISTER_SUCCESS_MESSAGE
            response.status_code = status.HTTP_201_CREATED
            app_logger.info("Registration successfully")
        except HTTPException as err:
            message = str(err)
            response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            app_logger.error(f"HTTPException ::: Error while Registration ::: {message}")
        except SQLAlchemyError as err:
            errors[type(err).__name__] = [str(err)]
            message = str(err)
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            app_logger.error(f"SQLAlchemyError ::: Error while Registration ::: {message}")
        except BadRequestException as err:
            response.status_code = status.HTTP_400_BAD_REQUEST
            message = err.msg
            app_logger.error(f"BadRequestException ::: Error while Registration ::: {message}")
        except Exception as err:
            errors[type(err).__name__] = [str(err)]
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error while Registration ::: {message}")
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def login(request: UserLoginRequest, response, db_interface: DBInterface) -> dict:
        data, message, errors = None, "", {}
        try:
            # Initialize DB Interface
            role_db_interface = DBInterface(Roles)

            # Convert request data to JSON
            request_data = convert_data_into_json(request)

            # Check if user exists
            user_object = await db_interface.get_single_item_by_filters({"email": request_data.get("email")})
            if not user_object:
                errors["email"] = [messages.ERR_EMAIL_INCORRECT]
                raise BadRequestException(messages.ERR_EMAIL_INCORRECT)

            # Verify password
            if not _hasher.verify_password(request_data.get("password"), user_object["password"]):
                errors["password"] = [messages.ERR_PASSWORD_INCORRECT]
                raise BadRequestException(messages.ERR_PASSWORD_INCORRECT)

            if user_object["is_verified"] != True:
                errors["permission"] = ["Email not verified"]
                raise JWTError("Email not verified")

            user_role = await role_db_interface.get_single_item_by_filters({"id": user_object["role_id"]})
            if not user_role:
                errors["role_id"] = [messages.ROLE_NOT_FOUND]
                raise BadRequestException(messages.ROLE_NOT_FOUND)
            user_object['role'] = user_role

            # Create access and refresh tokens
            access_token = jwt_authentication.create_access_token(payload={"sub": user_object["email"]})
            refresh_token = jwt_authentication.create_refresh_token(payload={"sub": user_object["email"]})

            data = {"token": {"access": access_token, "refresh": refresh_token}, "user": user_object}

            message = messages.LOGIN_SUCCESS_MESSAGE
            response.status_code = status.HTTP_200_OK
            app_logger.info("Login successfully")
        except ForbiddenException as err:
            response.status_code = status.HTTP_403_FORBIDDEN
            message = str(err)
            app_logger.error(f"ForbiddenException ::: Error while logging In ::: {message}")
            errors[type(err).__name__] = [str(err)]
        except SQLAlchemyError as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"SQLAlchemyError ::: Error while logging In ::: {message}")
            errors[type(err).__name__] = [str(err)]
        except JWTError as err:
            response.status_code = status.HTTP_401_UNAUTHORIZED
            message = str(err)
            app_logger.error(f"JWTError ::: Error while logging In ::: {message}")
            errors[type(err).__name__] = [str(err)]
        except BadRequestException as err:
            response.status_code = status.HTTP_400_BAD_REQUEST
            message = err.msg
            app_logger.error(f"BadRequestException ::: Error while logging In ::: {message}")
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error while logging In ::: {message}")
            errors[type(err).__name__] = [str(err)]
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def create_new_access_token(response, current_user: str) -> dict:
        data, message, errors = None, "", {}
        try:
            new_access_token = jwt_authentication.create_access_token(payload={"sub": current_user})
            new_refresh_token = jwt_authentication.create_refresh_token(payload={"sub": current_user})
            data = {"token": {"access": new_access_token, "refresh": new_refresh_token}}
            message = messages.CREATE_NEW_TOKEN_SUCCESS_MESSAGE
            response.status_code = status.HTTP_201_CREATED
        except JWTError as err:
            response.status_code = status.HTTP_401_UNAUTHORIZED
            message = str(err)
            app_logger.error(f"JWTError ::: Error while creating new token ::: {message}")
            errors[type(err).__name__] = [str(err)]
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error while creating new token ::: {message}")
            errors[type(err).__name__] = [str(err)]
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def change_password(request: PasswordChangeRequest, response, db_interface: DBInterface,
                              current_user) -> dict:
        data, message, errors = None, "", {}
        try:
            email_filter_list = {"email": current_user}
            user_object = await db_interface.get_single_item_by_filters(email_filter_list)
            # Verify old password
            if not _hasher.verify_password(request.old_password, user_object["password"]):
                errors["password"] = [messages.ERR_OlD_PASSWORD_INCORRECT]
                raise BadRequestException(messages.ERR_OlD_PASSWORD_INCORRECT)

            # Check if new password matches old password
            if _hasher.verify_password(request.new_password, user_object["password"]):
                errors["password"] = [messages.ERR_OLD_PASSWORD_MATCH]
                raise BadRequestException(messages.ERR_OLD_PASSWORD_MATCH)

            # Update user's password
            await db_interface.update(id=user_object["id"],
                                      data={"password": _hasher.get_password_hash(request.new_password)})
            message = messages.PASSWORD_CHANGE_MSG
            response.status_code = status.HTTP_200_OK
        except BadRequestException as err:
            response.status_code = status.HTTP_400_BAD_REQUEST
            message = err.msg
            app_logger.error(f"BadRequestException ::: Error in change password ::: {message}")
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error in change password ::: {message}")
            errors[type(err).__name__] = [str(err)]
        return {"results": {"data": data}, "message": message, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def forgot_password(request: ForgotPasswordRequest, response, db_interface: DBInterface,
                              background_tasks: BackgroundTasks) -> dict:
        data, message, errors = None, "", {}
        try:
            email_filter_list = {"email": request.email}
            user_object = await db_interface.get_single_item_by_filters(email_filter_list)
            if not user_object:
                errors["email"] = [messages.ERR_EMAIL_INCORRECT]
                raise BadRequestException(messages.ERR_EMAIL_INCORRECT)

            # Create password reset token
            reset_pass_token = jwt_authentication.create_token(payload={"sub": user_object["id"]},
                                                               secret_key=app_config.FORGOT_PASSWORD_TOKEN_SECRET_KEY,
                                                               expires_delta=timedelta(
                                                                   minutes=app_config.FORGOT_PASSWORD_EXPIRE_MINUTES))
            # Send password reset email
            background_tasks.add_task(
                _app_mail.send_mail,
                msg_schema=MessageSchema(subject="Password Reset Link",
                                         recipients=[user_object["email"]],
                                         template_body={
                                             "user_name": f'{user_object["first_name"]} {user_object["last_name"]}',
                                             "reset_link": app_config.FRONTEND_BASE_URL + app_config.RESET_TOKEN_ENDPOINT,
                                             "token": reset_pass_token
                                         },
                                         subtype="html"),
                template_name="forgot_password.html"
            )

            message = messages.PASSWORD_RESET_MAIL_MSG
            response.status_code = status.HTTP_200_OK
        except BadRequestException as err:
            response.status_code = status.HTTP_400_BAD_REQUEST
            message = err.msg
            app_logger.error(f"BadRequestException ::: Error in forgot password ::: {message}")
        except JWTError as err:
            response.status_code = status.HTTP_401_UNAUTHORIZED
            message = str(err)
            app_logger.error(f"JWTError ::: Error in forgot password ::: {message}")
            errors[type(err).__name__] = [str(err)]
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error in forgot password ::: {message}")
            errors[type(err).__name__] = [str(err)]
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def password_reset_confirm(request: SetpasswordRequest, response, reset_token: str,
                                     db_interface: DBInterface) -> dict:
        data, message, errors = None, "", {}
        try:
            # Instantiate DB interfaces
            blacklist_token_db_interface = DBInterface(BlackListTokens)

            # Check for token in blacklist
            if _ := await blacklist_token_db_interface.get_single_item_by_filters(
                    {"token": reset_token, "token_type": 'reset_token'}):
                errors["token"] = [messages.ERR_TOKEN_BLACKLISTED]
                raise TokenExpiryException(messages.ERR_TOKEN_BLACKLISTED)

            request_data = convert_data_into_json(request)
            user_id = jwt_authentication.decode_token(token=reset_token,
                                                      secret_key=app_config.FORGOT_PASSWORD_TOKEN_SECRET_KEY)
            if not password_validation(request_data.get("new_password")):
                errors["password"] = [messages.ERR_PASSWORD_WRONG]
                raise HTTPException(messages.ERR_PASSWORD_WRONG)

            request_data["password"] = _hasher.get_password_hash(request_data.get("new_password"))
            request_data.pop('new_password', None)

            await db_interface.update(id=user_id, data=request_data)

            # Blacklist the reset token
            _ = await blacklist_token_db_interface.create_with_uuid(
                data={"token_type": "reset_token", "token": reset_token, "user_id": user_id})
            message = messages.PASSWORD_CHANGE_MSG
            response.status_code = status.HTTP_200_OK
            app_logger.info(f"password reset successful ::: User-ID-{user_id}")
        except TokenExpiryException as err:
            response.status_code = status.HTTP_410_GONE
            message = str(err)
            app_logger.error(f"TokenExpiryException ::: Error in reset password ::: {message}")
        except (JWTError, SQLAlchemyError) as err:
            response.status_code = status.HTTP_401_UNAUTHORIZED
            message = str(err)
            app_logger.error(f"(JWTError, SQLAlchemyError) ::: Error in reset password ::: {message}")
            errors[type(err).__name__] = [str(err)]
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error in reset password ::: {message}")
            errors[type(err).__name__] = [str(err)]
        return {"results": {"data": data}, "message": message, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def add_tokens_to_blacklist(token_type: str, token: str, current_user: str) -> None:
        # Instantiate DB interfaces
        user_interface = DBInterface(User)
        black_list_token_interface = DBInterface(BlackListTokens)

        blacklist_obj = await black_list_token_interface.get_single_item_by_filters({"token": token})
        # Check if token already exists in the blacklist
        if not blacklist_obj:
            user_object = await user_interface.get_single_item_by_filters({"email": current_user})
            await black_list_token_interface.create_with_uuid(data={"token_type": token_type, "token": token,
                                                                    "user_id": user_object["id"], })

    @staticmethod
    async def revoke_tokens(request, response, access_token: str) -> dict:
        data, message, errors = None, "", {}
        try:
            access_token_secret = app_config.ACCESS_TOKEN_SECRET_KEY
            refresh_token_secret = app_config.REFRESH_TOKEN_SECRET_KEY
            refresh_token = request.refresh_token

            # Decode the token to get the current user for both access and refresh tokens
            current_user_acc_email = jwt_authentication.decode_token(token=access_token, secret_key=access_token_secret)
            current_user_refresh_email = jwt_authentication.decode_token(token=refresh_token,
                                                                         secret_key=refresh_token_secret)

            # Add both access and refresh tokens to the blacklist
            await UserAuthentication.add_tokens_to_blacklist(token_type="access_token", token=access_token,
                                                             current_user=current_user_acc_email)
            await UserAuthentication.add_tokens_to_blacklist(token_type="refresh_token", token=refresh_token,
                                                             current_user=current_user_refresh_email)
            message = messages.TOKEN_BLACKLIST_MSG
            response.status_code = status.HTTP_200_OK
            app_logger.info(f"Token Blacklisted successfully ::: User-Email-{current_user_acc_email}")
        except BadRequestException as err:
            response.status_code = status.HTTP_400_BAD_REQUEST
            message = err.msg
            app_logger.error(f"BadRequestException ::: Error in blacklisting tokens ::: {message}")
        except (JWTError, SQLAlchemyError) as err:
            response.status_code = status.HTTP_401_UNAUTHORIZED
            message = str(err)
            app_logger.error(f"(JWTError, SQLAlchemyError) ::: Error in blacklisting tokens ::: {message}")
            errors[type(err).__name__] = [str(err)]
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def user_profile(response, db_interface: DBInterface, current_user) -> dict:
        data, message, errors = None, "", {}
        try:
            # Initialize DB Interface
            role_db_interface = DBInterface(Roles)

            user_data = await db_interface.get_single_item_by_filters({"email": current_user})
            user_role = await role_db_interface.get_single_item_by_filters({'id': user_data['role_id']})
            user_data['role'] = user_role
            data = {"user": user_data}
            message = messages.GET_USER_PROFILE_MSG
            response.status_code = status.HTTP_200_OK
        except (JWTError, SQLAlchemyError) as err:
            errors[type(err).__name__] = [str(err)]
            response.status_code = status.HTTP_401_UNAUTHORIZED
            message = str(err)
            app_logger.error(f"(JWTError, SQLAlchemyError) ::: Error in fetching user ::: {message}")
        except Exception as err:
            errors[type(err).__name__] = [str(err)]
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
            app_logger.error(f"Exception ::: Error in fetching user ::: {message}")
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}

    @staticmethod
    async def change_profile(response, first_name: str, last_name: str, profile_image: Optional[UploadFile],
                             db_interface: DBInterface, current_user):
        data, message, errors = None, "", {}
        try:
            # Initialize DB Interface
            role_db_interface = DBInterface(Roles)

            email_filter_list = {"email": current_user}
            user_object = await db_interface.get_single_item_by_filters(email_filter_list)

            # Check if a profile image was uploaded
            if profile_image:
                # Generate a UUID for the filename
                filename = f"uploads/{uuid.uuid4()}.{profile_image.filename.split('.')[-1]}"  # Using UUID for filename
                # Save the profile image to a local directory
                with open(filename, "wb") as file:
                    file.write(profile_image.file.read())
            user_data = await db_interface.update(id=user_object["id"],
                                                  data={"first_name": first_name, "last_name": last_name,
                                                        "profile_image": f"{app_config.APP_URL}/{filename}" if profile_image else None})
            user_role = await role_db_interface.get_single_item_by_filters({'id': user_data['role_id']})
            user_data['role'] = user_role
            data = {"user": user_data}
            response.status_code = status.HTTP_200_OK
            message = messages.PROFILE_CHANGE_MSG
        except BadRequestException as err:
            response.status_code = status.HTTP_400_BAD_REQUEST
            message = err.msg
        except Exception as err:
            response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            message = str(err)
        return {"message": message, "results": {"data": data}, "status": response.status_code,
                "errors": {"message": errors}}
