"""FastAPI server configuration."""

import dataclasses
import os
from pathlib import Path

import dotenv
from fastapi_mongo_base.core import config

dotenv.load_dotenv()


@dataclasses.dataclass
class Settings(config.Settings):
    """Server config settings."""

    base_dir: Path = Path(__file__).resolve().parent.parent
    base_path: str = ""

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
