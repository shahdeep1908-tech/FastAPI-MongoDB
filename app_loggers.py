import logging
import os
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

from config import LogConfiguration, app_config

Path(LogConfiguration.log_file_base_dir).mkdir(parents=True, exist_ok=True)


def get_logger():
    """
    Logging Configurations.
    """
    logger = logging.getLogger(LogConfiguration.logger_name)
    formatter = logging.Formatter(LogConfiguration.logger_formatter)
    handler = TimedRotatingFileHandler(
        filename=os.path.join(LogConfiguration.log_file_base_dir,
                              LogConfiguration.log_file_base_name),
        when=LogConfiguration.roll_over,
        interval=1,
        backupCount=LogConfiguration.backup_count)
    handler.setFormatter(formatter)
    logger.setLevel(app_config.LOG_LEVEL)
    logger.addHandler(handler)
    return logger


app_logger = get_logger()
