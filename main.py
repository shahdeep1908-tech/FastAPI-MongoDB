import socketio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from common import constants
from config import app_config
import uvicorn

from ebds.workspace.workspace_model import create_worksapce_collection
from routes import router as api_router
from fastapi.middleware.cors import CORSMiddleware

from ebds.authentication.auth_model import create_auth_collection

from adapter.socket_manager import test_namespace
from socket_config import socket_io_server

origins = ['*']

app = FastAPI(title=constants.PROJECT_NAME,
              docs_url=constants.DOCS_URL_PATH,
              redoc_url=constants.REDOC_URL_PATH)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

"""Mount static files directory"""
app.mount('/uploads', StaticFiles(directory='uploads'), 'uploads')

"""Initialized routes.py file as api_router"""
app.include_router(api_router)


@app.on_event("startup")
async def startup_event():
    # Create collections for new models
    await create_auth_collection()
    await create_worksapce_collection()
    """
    initialize socket configuration once server starts.
    """
    socketio_server = socket_io_server.init(test_namespace=test_namespace)
    sio_app = socketio.ASGIApp(
        socketio_server=socketio_server, socketio_path="", other_asgi_app=app
    )
    app.mount("/socket.io", sio_app)

    return app


if __name__ == "__main__":
    uvicorn.run(app_config.FASTAPI_APP,
                host=app_config.HOST_URL,
                port=app_config.HOST_PORT,
                log_level=app_config.FASTAPI_LOG_LEVEL,
                reload=app_config.FASTAPI_APP_RELOAD)
