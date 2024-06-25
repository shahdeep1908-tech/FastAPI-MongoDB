from socketio import AsyncNamespace
from adapter.db_interface.db_interface_impl import DBInterface
from adapter.jwt_token_manager import JWTAuthenticator
from app_loggers import app_logger
from common import messages
from common.exceptions import BadRequestException
from common.utils import convert_data_into_json

from ebds.authentication.auth_model import User, Roles
from ebds.workspace.workspace_model import WorkspaceLists, Workspace, UserWorkSpace, WorkSpaceInviteMember, Permission, \
    Namespace
from ebds.workspace.workspace_schema import WorkspaceListUpdateSchema, MembersResponseData, ListResponse

jwt_authentication = JWTAuthenticator()


class TestNamespace(AsyncNamespace):

    async def get_nested_workspace_lists(self, workspace_list, db_interface):
        """Recursively retrieve nested pages."""
        result = {
            "id": workspace_list['id'],
            "title": workspace_list['title'],
            "content": workspace_list['content'],
            "table_view": workspace_list['table_view'],
            "parent_id": workspace_list['parent_id'],
            "children": []
        }

        child_lists = await db_interface.get_multiple_items_by_filters(
            (('parent_id', workspace_list['id']), ('is_deleted', False)))
        for child in child_lists:
            result["children"].append(await self.get_nested_workspace_lists(child, db_interface))
        return result

    async def on_connect(self, sid, environ, auth: dict | str) -> None:
        """
        Event received when client wants to connect.
        """
        # TODO ::: uncomment auth code

        # app_logger.info(f"Access Token :: {environ.get('HTTP_ACCESS_TOKEN') or None} ::: Auth ::{auth}")
        # auth = auth or environ.get('HTTP_ACCESS_TOKEN')
        # if auth is None:
        #     app_logger.error("Exception ::: Access token not provided.")
        #     raise ConnectionRefusedError("Access token not provided.")
        # if isinstance(auth, dict):
        #     current_user_email = self.get_user_email_from_access_token(auth['token'])
        # else:
        #     current_user_email = self.get_user_email_from_access_token(auth)
        # user_db_interface = DBInterface(User)
        # current_user_object = user_db_interface.get_single_item_by_filters((User.email == current_user_email,))

        app_logger.info(f"New user session connected :: {sid}")
        room_name = "test_room"
        await self.enter_room(sid, room_name)
        await self.emit(
            "userConnected",
            {"data": "User has been connected", "sid": sid},
            namespace=self.namespace,
        )

    async def on_disconnect(self, sid) -> None:
        """
        Event received when client wants to disconnect.
        """
        try:
            app_logger.info(f"User session disconnected :: {sid}")
            await self.emit(
                "userDisconnected",
                {"data": "User has been disconnected", "sid": sid},
                namespace=self.namespace,
            )
        except Exception as err:
            app_logger.error(f"Exception ::: Error while disconnecting user session ::: {str(err)}")

    async def on_message(self, sid, data) -> str:
        """
        Event received when client sends a text message.
        """
        print("Message sent is ::", data)
        await self.emit(
            "userMessage",
            {"message_data": data, "sid": sid},
            namespace=self.namespace,
        )
        return "OK"

    async def on_create_list(self, sid, request_data) -> None:
        """
        Event received when client creates a new page.
        """
        data, message, errors, status_code = None, "", {}, 201
        try:
            if not request_data:
                errors['data'] = [messages.LIST_DATA_NOT_FOUND]
                app_logger.error(
                    f" Error occurred while creating a new workspace list ::: {str(messages.LIST_DATA_NOT_FOUND)}")
                raise BadRequestException(messages.LIST_DATA_NOT_FOUND)

            workspace_db_interface = DBInterface(Workspace)
            permission_db_interface = DBInterface(Permission)
            namespace_db_interface = DBInterface(Namespace)
            workspace_list_db_interface = DBInterface(WorkspaceLists)

            workspace_obj = await workspace_db_interface.get_single_item_by_filters(
                {'id': request_data['workspace_id'], 'is_deleted': False})
            if not workspace_obj:
                errors['workspace'] = [messages.WORKSPACE_NOT_FOUND]
                app_logger.error(
                    f"Error occurred while creating a new workspace list ::: {str(messages.WORKSPACE_NOT_FOUND)}")
                raise BadRequestException(messages.WORKSPACE_NOT_FOUND)
            workspace_obj['permission'] = await permission_db_interface.get_single_item_by_filters(
                {'id': workspace_obj['permission_id']})
            workspace_obj['namespace'] = await namespace_db_interface.get_single_item_by_filters(
                {'id': workspace_obj['namespace_id']})

            if request_data["parent_id"] is not None:
                workspace_list_obj = await workspace_list_db_interface.get_single_item_by_filters(
                    {'id': request_data["parent_id"], 'is_deleted': False})
                if not workspace_list_obj:
                    errors['list'] = [messages.PARENT_LIST_NOT_FOUND]
                    app_logger.error(
                        f"Error occurred while creating a new workspace list ::: {str(messages.PARENT_LIST_NOT_FOUND)}")
                    raise BadRequestException(messages.PARENT_LIST_NOT_FOUND)

            workspace_list = await workspace_list_db_interface.create_with_uuid(data=request_data)
            data = {"lists": await self.get_nested_workspace_lists(workspace_list, workspace_list_db_interface),
                    "workspace": workspace_obj}
            json_data = convert_data_into_json(data)
            modified_data = ListResponse.model_validate(json_data)
            data = convert_data_into_json(modified_data)
            message = messages.LIST_SUCCESS_MESSAGE.format("created")
        except BadRequestException as err:
            message = str(err)
            status_code = 400
        except Exception as err:
            status_code = 500
            message = str(err)
        data = {"message": message, "results": {"data": data}, "status": status_code, "errors": {"message": errors}}
        await self.emit(
            "newListCreated",
            {"data": data, "sid": sid},
            namespace=self.namespace,
        )

    async def on_title_change(self, sid, request_data) -> None:
        """
        Event received when client changes page title.
        """
        data, message, errors, status_code = None, "", {}, 200
        try:
            if not request_data:
                errors['data'] = [messages.LIST_DATA_NOT_FOUND]
                app_logger.error(f"  ::: {str(messages.LIST_DATA_NOT_FOUND)}")
                raise BadRequestException(messages.LIST_DATA_NOT_FOUND)

            workspace_list_db_interface = DBInterface(WorkspaceLists)

            list_id = request_data['id']
            list_obj = await workspace_list_db_interface.get_single_item_by_filters(
                {'id': list_id, 'is_deleted': False})
            if not list_obj:
                errors['workspace_list'] = [messages.LIST_NOT_FOUND]
                app_logger.error(
                    f"Error occurred while updating workspace list title ::: {str(messages.LIST_NOT_FOUND)}")
                raise BadRequestException(messages.LIST_NOT_FOUND)

            new_title = request_data['title'].strip().replace(" ", "-")
            new_list = await workspace_list_db_interface.update(id=list_id, data={'title': new_title})
            json_data = convert_data_into_json(new_list)
            modified_data = WorkspaceListUpdateSchema.model_validate(json_data)
            data = convert_data_into_json(modified_data)
            message = messages.LIST_TITLE_CHANGED
        except BadRequestException as err:
            message = str(err)
            status_code = 400
        except Exception as err:
            status_code = 500
            message = str(err)
        data = {"message": message, "results": {"data": data}, "status": status_code, "errors": {"message": errors}}
        await self.emit(
            "listTitleChanged",
            {"data": data, "sid": sid},
            namespace=self.namespace,
        )

    async def on_delete_list(self, sid, request_data) -> None:
        """
        Event received when client deletes a page.
        """
        data, message, errors, status_code = None, "", {}, 204
        try:
            if not request_data:
                errors['data'] = [messages.LIST_DATA_NOT_FOUND]
                app_logger.error(
                    f" Error occurred while deleting a workspace list ::: {str(messages.LIST_DATA_NOT_FOUND)}")
                raise BadRequestException(messages.LIST_DATA_NOT_FOUND)

            workspace_list_db_interface = DBInterface(WorkspaceLists)

            workspace_list_obj = await workspace_list_db_interface.get_single_item_by_filters(
                {'id': request_data['list_id'], 'is_deleted': False})
            if not workspace_list_obj:
                errors['workspace_list'] = [messages.LIST_NOT_FOUND]
                app_logger.error(f"Error occurred while deleting a workspace list ::: {str(messages.LIST_NOT_FOUND)}")
                raise BadRequestException(messages.LIST_NOT_FOUND)

            _ = await workspace_list_db_interface.update(id=request_data['list_id'], data={'is_deleted': True})
            message = messages.LIST_SUCCESS_MESSAGE.format("deleted")
        except BadRequestException as err:
            message = str(err)
            status_code = 400
        except Exception as err:
            status_code = 500
            message = str(err)
        data = {"message": message, "results": {"data": data}, "status": status_code,
                "errors": {"message": errors}}
        await self.emit(
            "listDeleted",
            {"data": data, "sid": sid},
            namespace=self.namespace,
        )

    async def on_update_list(self, sid, request_data) -> None:
        """
        Event received when client updates page.
        """
        data, message, errors, status_code = None, "", {}, 200
        try:
            if not request_data:
                errors['data'] = [messages.LIST_DATA_NOT_FOUND]
                app_logger.error(
                    f" Error occurred while updating a workspace list ::: {str(messages.LIST_DATA_NOT_FOUND)}")
                raise BadRequestException(messages.LIST_DATA_NOT_FOUND)

            workspace_list_db_interface = DBInterface(WorkspaceLists)

            workspace_list_obj = workspace_list_db_interface.get_single_item_by_filters(
                {'id': request_data['list_id'], 'is_deleted': False})
            if not workspace_list_obj:
                errors['workspace_list'] = [messages.LIST_NOT_FOUND]
                app_logger.error(f"Error occurred while updating a workspace list ::: {str(messages.LIST_NOT_FOUND)}")
                raise BadRequestException(messages.LIST_NOT_FOUND)

            updated_page = await workspace_list_db_interface.update(id=request_data['list_id'],
                                                                    data={'content': request_data['content'],
                                                                          'table_view': request_data['table_view']})
            json_data = convert_data_into_json(updated_page)
            modified_data = WorkspaceListUpdateSchema.model_validate(json_data)
            data = convert_data_into_json(modified_data)
            message = messages.LIST_SUCCESS_MESSAGE.format("updated")
        except BadRequestException as err:
            message = str(err)
            status_code = 400
        except Exception as err:
            status_code = 500
            message = str(err)
        data = {"message": message, "results": {"data": data}, "status": status_code, "errors": {"message": errors}}
        await self.emit(
            "listUpdated",
            {"data": data, "sid": sid},
            namespace=self.namespace,
        )

    async def on_workspace_members(self, sid, request_data):
        """
            Event received to retrieve members of a workspace.
        """
        data, message, errors, status_code = None, "", {}, 200
        try:
            workspace_db_interface = DBInterface(Workspace)
            permission_db_interface = DBInterface(Permission)
            namespace_db_interface = DBInterface(Namespace)
            user_workspace_db_interface = DBInterface(UserWorkSpace)
            invite_member_db_interface = DBInterface(WorkSpaceInviteMember)
            user_db_interface = DBInterface(User)
            role_db_interface = DBInterface(Roles)

            if not request_data:
                errors['data'] = [messages.PAGE_DATA_NOT_FOUND]
                app_logger.error(f" Error occurred while retrieving members ::: {str(messages.PAGE_DATA_NOT_FOUND)}")
                raise BadRequestException(messages.PAGE_DATA_NOT_FOUND)

            workspace_id = request_data['workspace_id']
            workspace_object = await workspace_db_interface.get_single_item_by_filters(
                {'id': workspace_id, 'is_deleted': False})
            if not workspace_object:
                errors["workspace"] = [messages.WORKSPACE_NOT_FOUND]
                raise BadRequestException(messages.WORKSPACE_NOT_FOUND)
            workspace_object['permission'] = await permission_db_interface.get_single_item_by_filters(
                {'id': workspace_object['permission_id']})
            workspace_object['namespace'] = await namespace_db_interface.get_single_item_by_filters(
                {'id': workspace_object['namespace_id']})

            members_data = await user_workspace_db_interface.get_multiple_items_by_filters(
                (('workspace_id', workspace_id),))
            for member_data in members_data:
                member_data['user'] = await user_db_interface.get_single_item_by_filters({'id': member_data['user_id']})
                member_data['user']['role'] = await role_db_interface.get_single_item_by_filters(
                    {'id': member_data['role_id']})

            invited_members_data = await invite_member_db_interface.get_multiple_items_by_filters((
                ('workspace_id', workspace_id), ('is_accepted', False,)))
            for invited_member_data in invited_members_data:
                invited_member_data['role'] = await role_db_interface.get_single_item_by_filters(
                    {'id': invited_member_data['role_id']})

            workspace_members_data = {"members": members_data, "invited_members": invited_members_data,
                                      "workspace": workspace_object}
            json_data = convert_data_into_json(workspace_members_data)
            modified_data = MembersResponseData.model_validate(json_data)
            data = convert_data_into_json(modified_data)
            message = messages.WORKSPACE_MEMBERS_SUCCESS
        except BadRequestException as err:
            message = str(err)
            status_code = 400
        except Exception as err:
            status_code = 500
            message = str(err)
        data = {"message": message, "results": {"data": data}, "status": status_code,
                "errors": {"message": errors}}
        await self.emit(
            "workspaceMembers",
            {"data": data, "sid": sid},
            namespace=self.namespace,
        )


test_namespace = TestNamespace(namespace="/test")
