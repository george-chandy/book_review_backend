from datetime import datetime, timezone, timedelta
import uuid
from sqlalchemy.orm import Session

from src.auth.config import config
from src.auth.authorize import UserRole
from src.auth.models import EmailVerificationToken, User, PasswordResetToken


def get_user_by_id(db: Session, user_id: int) -> User:
    return db.query(User).get(user_id)


def get_user_by_email(db: Session, email: str) -> User:
    return db.query(User).filter(User.email == email).first()


def is_email_taken(db: Session, email: str) -> bool:
    return get_user_by_email(db, email) is not None


def register_user(
    db: Session,
    first_name,
    last_name,
    email,
    phone,
    hashed_password,
    role=UserRole.STUDENT,
    is_email_verified=False,
) -> User:
    db_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        phone=phone,
        password=hashed_password,
        role=str(role.value),
        is_email_verified=is_email_verified,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_email_verification_token(db: Session, user_id: int) -> str:
    token = uuid.uuid4()
    current_time = datetime.now(timezone.utc)
    expiry_time = current_time + timedelta(
        hours=config.EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS
    )

    db_token = EmailVerificationToken(
        user_id=user_id,
        token=token,
        created_at=current_time,
        expires_at=expiry_time,
    )

    db.add(db_token)
    db.commit()
    return token


def get_user_id_by_email_token(db: Session, token: str) -> int:
    db_token = (
        db.query(EmailVerificationToken)
        .filter(EmailVerificationToken.token == token)
        .one_or_none()
    )

    if not db_token:
        return

    user_id = db_token.user_id
    current_time = datetime.now(timezone.utc)
    if current_time > db_token.expires_at:
        return

    return user_id


def mark_email_verified(db: Session, user_id: int) -> None:
    db.query(User).filter(User.id == user_id).update({"is_email_verified": True})
    db.commit()


def delete_email_tokens(db: Session, user_id: int) -> str:
    db.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user_id,
    ).delete()
    db.commit()


def create_password_reset_token(db: Session, user_id: int) -> str:
    token = uuid.uuid4()
    current_time = datetime.now(timezone.utc)
    expiry_time = current_time + timedelta(
        hours=config.PASSWORD_RESET_TOKEN_EXPIRY_HOURS
    )

    db_token = PasswordResetToken(
        user_id=user_id,
        token=token,
        created_at=current_time,
        expires_at=expiry_time,
    )

    db.add(db_token)
    db.commit()
    return token


def get_user_id_by_password_token(db: Session, token: str) -> int:
    db_token = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token == token,
        )
        .one_or_none()
    )

    if not db_token:
        return

    user_id = db_token.user_id
    current_time = datetime.now(timezone.utc)
    if current_time > db_token.expires_at:
        return

    return user_id


def update_user_password(db: Session, user_id: int, hashed_password: str) -> None:
    db.query(User).filter(User.id == user_id).update({"password": hashed_password})
    db.commit()


def delete_password_tokens(db: Session, user_id) -> None:
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user_id,
    ).delete()
    db.commit()
