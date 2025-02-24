from fastapi_mail import ConnectionConfig, FastMail, MessageSchema

from src.config import config


class EmailConfig(ConnectionConfig):
    MAIL_USERNAME: str = config.MAIL_USERNAME
    MAIL_PASSWORD: str = config.MAIL_PASSWORD
    MAIL_FROM: str = config.MAIL_FROM
    MAIL_PORT: int = config.MAIL_PORT
    MAIL_SERVER: str = config.MAIL_SERVER
    MAIL_STARTTLS: bool = config.MAIL_STARTTLS
    MAIL_SSL_TLS: bool = config.MAIL_SSL_TLS
    USE_CREDENTIALS: bool = config.USE_CREDENTIALS
    VALIDATE_CERTS: bool = config.VALIDATE_CERTS


# Initialize FastMail
mail_config = EmailConfig()
fm = FastMail(mail_config)


async def send_email(message: MessageSchema):
    await fm.send_message(message)
