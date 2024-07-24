"""FastAPI server configuration."""

import dataclasses
import logging
import logging.config
import os
from pathlib import Path

import dotenv
from singleton import Singleton

dotenv.load_dotenv()


@dataclasses.dataclass
class Settings(metaclass=Singleton):
    """Server config settings."""

    base_dir = Path(__file__).resolve().parent.parent
    root_url: str = os.getenv("DOMAIN", default="http://localhost:8000")
    mongo_uri: str = os.getenv("MONGO_URI")
    redis_uri: str = os.getenv("REDIS_URI")
    project_name: str = os.getenv("PROJECT_NAME")

    # Security settings
    secret_key: str = os.getenv("SECRET_KEY")
    salt: bytes = os.getenv("SALT").encode()
    RSA_PASSWORD: bytes = os.getenv("RSA_PASSWORD").encode()

    # FastMail SMTP server settings
    mail_server: str = os.getenv("SMTP_HOST", default="smtp.myserver.io")
    mail_port: int = os.getenv("SMTP_PORT", default=587)
    mail_username: str = os.getenv("SMTP_USER", default="")
    mail_password: str = os.getenv("SMTP_PASS", default="")
    mail_sender: str = os.getenv("SMTP_SENDER", default="noreply@myserver.io")
    mail_console: bool = os.getenv("SMTP_NO_SEND_SHOW_CONSOLE", default=False)

    testing: bool = os.getenv("TESTING", default=False)

    log_config = {
        "version": 1,
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "standard",
            },
            "file": {
                "class": "logging.FileHandler",
                "level": "DEBUG",
                "filename": base_dir / "logs" / "info.log",
                "formatter": "standard",
            },
        },
        "formatters": {
            "standard": {
                "format": "[{levelname} : {filename}:{lineno} : {asctime} -> {funcName:10}] {message}",
                "style": "{",
            }
        },
        "loggers": {
            "": {
                "handlers": [
                    "console",
                    "file",
                ],
                "level": (
                    "INFO"
                    if os.getenv("TESTING", default="").lower() not in ["true", "1"]
                    else "DEBUG"
                ),
                "propagate": True,
            },
        },
    }

    @classmethod
    def config_logger(cls):
        if not (cls.base_dir / "logs").exists():
            (cls.base_dir / "logs").mkdir()

        logging.config.dictConfig(cls.log_config)
