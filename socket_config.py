from typing import Any

import socketio

from adapter.db_interface.db_interface_impl import DBInterface
from adapter.socket_manager import TestNamespace
from ebds.workspace.workspace_model import Namespace


class SocketIOServer:

    def __init__(self):
        self.sio = socketio.AsyncServer(
            async_mode="asgi",
            cors_allowed_origins=["*"],
            logger=True,
            engineio_logger=True,
        )

    async def init(self, test_namespace: TestNamespace, *args: Any, **kwargs: Any) -> socketio.AsyncServer:
        self.sio.register_namespace(test_namespace)
        namespace_db_interface = DBInterface(Namespace)
        namespace_obj = await namespace_db_interface.read_all()
        for namespaces in namespace_obj:
            self.sio.register_namespace(TestNamespace(namespace=f"/{namespaces['name']}"))
        return self.sio

    def register_new_namespace(self, namespace: str) -> None:
        self.sio.register_namespace(TestNamespace(namespace=f"/{namespace}"))

    def shutdown(self, connection: socketio.AsyncServer) -> None:
        # TODO: Implement shutdown logic
        pass


socket_io_server = SocketIOServer()
