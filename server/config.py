"""FastAPI server configuration."""

import os

import dotenv
from pydantic import BaseModel

dotenv.load_dotenv()


class Settings(BaseModel):
    """Server config settings."""

    root_url: str = os.getenv("DOMAIN", default="http://localhost:8000")

    # Mongo Engine settings
    mongo_uri: str = os.getenv("MONGO_URI")

    # Redis settings
    redis_uri: str = os.getenv("REDIS_URI")

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


CONFIG = Settings()
