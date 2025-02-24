from datetime import datetime, timedelta, timezone
import re
from typing import Dict
from uuid import UUID

import bcrypt
from fastapi_mail import MessageSchema, MessageType
import jwt

from src.auth.config import config
from src.auth.exceptions import JwtTokenExpiredException
from src.auth.models import User
from src.auth.schemas import TokenData, TokenType, UserRole
from src.mail import send_email


def is_valid_email(email: str) -> bool:
    """
    Check if the given string is a valid email address.

    An email is considered valid if it contains at least one character before '@',
    followed by a domain name with a '.' and at least one character after it.
    """

    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))


def is_valid_phone(phone: str) -> bool:
    """Check if the phone number is exactly 10 digits."""

    return bool(re.match(r"^\d{10}$", phone))


def is_password_complex(password: str) -> bool:
    """
    Checks if the given password meets complexity requirements.

    Requirements:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character (e.g., @, #, $, etc.)

    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed_password.decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a password against a hashed password using bcrypt."""

    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


def is_valid_uuid(uuid, version=4):
    """Check if uuid is a valid UUID."""

    try:
        uuid_obj = UUID(uuid, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid


async def send_verification_email(user: User, verification_token: str):
    subject = "Verify Your Email Address with Atom IAS"
    body = f"""
    Dear {user.first_name} {user.last_name},

    Thank you for registering with Atom IAS! We're excited to have you as part of our learning community.
    To complete your registration and get started, please verify your email address by clicking the link below:

    {config.HOST_ADDRESS}/verify-email?token={verification_token}
    """

    message = MessageSchema(
        recipients=[user.email], subject=subject, body=body, subtype=MessageType.plain
    )
    await send_email(message=message)


def create_access_token(user_id, role: UserRole) -> str:
    current_time = datetime.now(timezone.utc)
    expiry_time = current_time + timedelta(minutes=config.JWT_ACCESS_EXPIRY_MINUTES)
    payload = {
        "sub": str(user_id),
        "role": role.value,
        "iat": current_time,
        "exp": expiry_time,
        "aud": config.JWT_AUDIENCE,
        "iss": config.JWT_ISSUER,
        "type": TokenType.ACCESS.value,
    }
    return jwt.encode(payload, config.JWT_ACCESS_SECRET, algorithm="HS256")


def create_refresh_token(user_id, role: UserRole) -> str:
    current_time = datetime.now(timezone.utc)
    expiry_time = current_time + timedelta(days=config.JWT_REFRESH_EXPIRY_DAYS)
    payload = {
        "sub": str(user_id),
        "role": role.value,
        "iat": current_time,
        "exp": expiry_time,
        "aud": config.JWT_AUDIENCE,
        "iss": config.JWT_ISSUER,
        "type": TokenType.REFRESH.value,
    }
    return jwt.encode(payload, config.JWT_REFRESH_SECRET, algorithm="HS256")


def validate_and_decode_token(token: str, token_type: TokenType) -> TokenData | None:
    """
    Returns: token data if token is valid else return None.
    Exception: JwtTokenExpiredException <- if token is expired
    """

    secrets = {
        TokenType.ACCESS: config.JWT_ACCESS_SECRET,
        TokenType.REFRESH: config.JWT_REFRESH_SECRET,
    }

    try:
        payload: Dict = jwt.decode(
            token,
            secrets[token_type],
            ["HS256"],
            audience=config.JWT_AUDIENCE,
            issuer=config.JWT_ISSUER,
        )

        user_role = payload.get("role")
        user_id = payload.get("sub")
        if not user_id or not user_role:
            return

        return TokenData(user_id=int(user_id), user_role=user_role)
    except jwt.exceptions.ExpiredSignatureError:
        raise JwtTokenExpiredException()
    except jwt.exceptions.InvalidTokenError:
        return
    except Exception:
        return


async def send_reset_email(user: User, reset_token: str):
    subject = "Reset Your Password with Atom IAS"
    body = f"""
    Dear {user.first_name} {user.last_name},
    We received a request to reset the password for your Atom IAS account. You can reset your password by clicking the link below:

    {config.HOST_ADDRESS}/reset-password?token={reset_token}

    If you didn't request a password reset, please ignore this email. Your password will remain unchanged.

    Best regards,  
    The Atom IAS Team
    """

    message = MessageSchema(
        recipients=[user.email], subject=subject, body=body, subtype=MessageType.plain
    )
    await send_email(message=message)
