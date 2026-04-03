import logging
import os, sys

from api.utils.settings import BASE_DIR

def create_logger(name: str, log_file: str='logs/app_logs.log') -> logging.Logger:
    """
    Create a logger with the specified name and log file.

    Args:
        name (str): The name of the logger.
        log_file (str): The path to the log file.

    Returns:
        logging.Logger: Configured logger instance.
    """
    
    os.makedirs(f'{BASE_DIR}/logs', exist_ok=True)
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(filename)s:%(module)s:%(funcName)s: line %(lineno)d:- %(message)s"
    )

    # Add formatter to handlers
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

def log_error(logger: logging.Logger, exc, message: str):
    exc_type, exc_obj, exc_tb = sys.exc_info()
    logger.error(message, stacklevel=2)
    logger.error(f"[ERROR] - An error occured | {exc}\n{exc_type}\n{exc_obj}\nLine {exc_tb.tb_lineno}", stacklevel=2)
