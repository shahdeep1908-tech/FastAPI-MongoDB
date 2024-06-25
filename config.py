import os
from functools import lru_cache

from fastapi_mail import ConnectionConfig
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")


class ServerType(BaseModel):
    PRODUCTION: str = "production"
    DEVELOPMENT: str = "development"
    LOCAL: str = "local"


class Setting(BaseSettings):
    HOST_URL: str
    HOST_PORT: int
    DATABASE_URL: str
    DB_NAME: str
    DATABASE_CONNECTION_TIMEOUT: str
    FASTAPI_LOG_LEVEL: str
    LOG_LEVEL: str
    APP_URL: str
    ENV_FASTAPI_SERVER_TYPE: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_SECRET_KEY: str
    REFRESH_TOKEN_SECRET_KEY: str
    FORGOT_PASSWORD_TOKEN_SECRET_KEY: str
    VERIFY_EMAIL_TOKEN_SECRET_KEY: str
    REFRESH_TOKEN_EXPIRE_MINUTES: int
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    FORGOT_PASSWORD_EXPIRE_MINUTES: int
    VERIFY_EMAIL_EXPIRE_MINUTES: int
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_FROM_NAME: str
    MAIL_TLS: bool = True
    MAIL_SSL: bool = False
    USE_CREDENTIALS: bool = True
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "smtp.gmail.com"
    FRONTEND_BASE_URL: str
    RESET_TOKEN_ENDPOINT: str
    FRONTEND_LOGIN_ENDPOINT: str
    FRONTEND_VERIFY_EMAIL_ENDPOINT: str

    class Config:
        env_nested_delimiter = '__'
        env_file = ".env"
        env_file_encoding = "utf-8"


app_settings = Setting()
_app_server_type = ServerType()


@lru_cache
def get_current_server_config():
    """
    This will check FASTAPI_ENV variable and create an object of configuration according to that.
    :return: Production or Development Config object.
    """
    server_type = os.getenv("ENV_FASTAPI_SERVER_TYPE", _app_server_type.LOCAL)
    if server_type == _app_server_type.DEVELOPMENT:
        return DevelopmentConfig(_app_server_type.DEVELOPMENT)
    elif server_type == _app_server_type.PRODUCTION:
        return ProductionConfig(_app_server_type.PRODUCTION)
    return LocalConfig(_app_server_type.LOCAL)


class Config(object):
    """
    Set base configuration, env variable configuration and server configuration.
    """

    def __init__(self, server_type: str):
        self.SERVER_TYPE = server_type

    """ The starting execution point of the app."""
    FASTAPI_APP = "main:app"
    FASTAPI_APP_RELOAD = True

    DEBUG: bool = False
    TESTING: bool = False
    HOST_URL = app_settings.HOST_URL
    HOST_PORT = app_settings.HOST_PORT
    DATABASE_URL = app_settings.DATABASE_URL
    DB_NAME = app_settings.DB_NAME
    DATABASE_CONNECTION_TIMEOUT = app_settings.DATABASE_CONNECTION_TIMEOUT
    FASTAPI_LOG_LEVEL = app_settings.FASTAPI_LOG_LEVEL
    LOG_LEVEL = app_settings.LOG_LEVEL
    APP_URL = app_settings.APP_URL
    ENV_FASTAPI_SERVER_TYPE = app_settings.ENV_FASTAPI_SERVER_TYPE
    JWT_ALGORITHM = app_settings.JWT_ALGORITHM
    ACCESS_TOKEN_SECRET_KEY = app_settings.ACCESS_TOKEN_SECRET_KEY
    REFRESH_TOKEN_SECRET_KEY = app_settings.REFRESH_TOKEN_SECRET_KEY
    FORGOT_PASSWORD_TOKEN_SECRET_KEY = app_settings.FORGOT_PASSWORD_TOKEN_SECRET_KEY
    VERIFY_EMAIL_TOKEN_SECRET_KEY = app_settings.VERIFY_EMAIL_TOKEN_SECRET_KEY
    REFRESH_TOKEN_EXPIRE_MINUTES = app_settings.REFRESH_TOKEN_EXPIRE_MINUTES
    ACCESS_TOKEN_EXPIRE_MINUTES = app_settings.ACCESS_TOKEN_EXPIRE_MINUTES
    FORGOT_PASSWORD_EXPIRE_MINUTES = app_settings.FORGOT_PASSWORD_EXPIRE_MINUTES
    VERIFY_EMAIL_EXPIRE_MINUTES = app_settings.VERIFY_EMAIL_EXPIRE_MINUTES
    MAIL_USERNAME = app_settings.MAIL_USERNAME
    MAIL_PASSWORD = app_settings.MAIL_PASSWORD
    MAIL_FROM = app_settings.MAIL_FROM
    MAIL_FROM_NAME = app_settings.MAIL_FROM_NAME
    MAIL_TLS = app_settings.MAIL_TLS
    MAIL_SSL = app_settings.MAIL_SSL
    USE_CREDENTIALS = app_settings.USE_CREDENTIALS
    MAIL_PORT = app_settings.MAIL_PORT
    MAIL_SERVER = app_settings.MAIL_SERVER
    FRONTEND_BASE_URL = app_settings.FRONTEND_BASE_URL
    RESET_TOKEN_ENDPOINT = app_settings.RESET_TOKEN_ENDPOINT
    FRONTEND_LOGIN_ENDPOINT = app_settings.FRONTEND_LOGIN_ENDPOINT
    FRONTEND_VERIFY_EMAIL_ENDPOINT = app_settings.FRONTEND_VERIFY_EMAIL_ENDPOINT


class LogConfiguration:
    """
    This class is used for the configuration of Logs
    """
    logger_name: str = "EBDS"
    logger_formatter: str = "%(asctime)s-%(levelname)s-%(name)s-%(process)d-%(pathname)s|%(lineno)s:: %(funcName)s|%(" \
                            "lineno)s:: %(message)s "
    roll_over: str = "MIDNIGHT"
    backup_count: int = 90
    log_file_base_name: str = "log"
    log_file_base_dir: str = f"{os.getcwd()}/logs"


class LocalConfig(Config):
    """
    This class used to generate the config for the development instance.
    """
    DEBUG: bool = True
    TESTING: bool = True


class DevelopmentConfig(Config):
    """
    This class used to generate the config for the development instance.
    """
    DEBUG: bool = True
    TESTING: bool = True


class ProductionConfig(Config):
    """
    This class used to generate the config for the production instance.
    """


class MailConfig:
    """
    This class used to generate the config for the Mail instance.
    """

    @staticmethod
    def connection_config():
        """
        :return: connection config object.
        """
        return ConnectionConfig(
            MAIL_USERNAME=app_config.MAIL_USERNAME,
            MAIL_PASSWORD=app_config.MAIL_PASSWORD,
            MAIL_FROM=app_config.MAIL_FROM,
            MAIL_PORT=app_config.MAIL_PORT,
            MAIL_SERVER=app_config.MAIL_SERVER,
            MAIL_FROM_NAME=app_config.MAIL_FROM_NAME,
            MAIL_STARTTLS=True,
            MAIL_SSL_TLS=False,
            USE_CREDENTIALS=app_config.USE_CREDENTIALS,
            TEMPLATE_FOLDER='templates',
        )


app_config = get_current_server_config()
