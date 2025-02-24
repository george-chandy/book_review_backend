from fastapi import APIRouter, Depends, Request, Response, Security, status

from src.auth import models
from src.auth.authorize import auth_user_id, auth_user_id_by_roles
from src.auth.service import (
    create_email_verification_token,
    create_password_reset_token,
    delete_email_tokens,
    delete_password_tokens,
    get_user_by_email,
    get_user_by_id,
    get_user_id_by_email_token,
    get_user_id_by_password_token,
    is_email_taken,
    mark_email_verified,
    register_user,
    update_user_password,
)
from src.database import get_db
from src.auth.utils import (
    create_access_token,
    create_refresh_token,
    hash_password,
    is_password_complex,
    is_valid_email,
    is_valid_phone,
    is_valid_uuid,
    send_verification_email,
    validate_and_decode_token,
    verify_password,
    send_reset_email,
)
from src.auth.schemas import (
    AdminRegisterUserRequest,
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    RefreshTokenResponse,
    RegisterRequest,
    RegisterResponse,
    TokenType,
    User,
    UserRole,
    VerifyEmailRequest,
    ResendVerificationMailRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from src.auth.exceptions import (
    EmailAlreadyRegisteredException,
    EmailNotVerifiedException,
    EmailRequiredException,
    FirstNameRequiredException,
    IncorrectOldPasswordException,
    InvalidCredentialsException,
    InvalidEmailException,
    InvalidEmailFormatException,
    InvalidOrExpiredEmailTokenException,
    InvalidOrExpiredResetTokenException,
    InvalidOrExpiredTokenException,
    InvalidPhoneFormatException,
    JwtTokenExpiredException,
    LastNameRequiredException,
    NewPasswordRequiredException,
    PasswordRequiredException,
    PasswordTooWeakException,
    PhoneRequiredException,
    RefreshTokenRequiredException,
    EmailAlreadyVerifiedException,
    EmailNotRegisteredException,
    ResetTokenRequiredException,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login")
async def login(
    login_request: LoginRequest, response: Response, db=Depends(get_db)
) -> LoginResponse:
    email, password = login_request.email.strip(), login_request.password.strip()
    if not email:
        raise EmailRequiredException()
    if not password:
        raise PasswordRequiredException()

    db_user: models.User = get_user_by_email(db, email)
    if not db_user:
        raise InvalidCredentialsException()
    if not verify_password(password, db_user.password):
        raise InvalidCredentialsException()
    if not db_user.is_email_verified:
        raise EmailNotVerifiedException()

    access_token = create_access_token(db_user.id, UserRole(db_user.role))
    refresh_token = create_refresh_token(db_user.id, UserRole(db_user.role))

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/auth/refresh-token",
    )

    user = User.model_validate(db_user)
    return LoginResponse(access_token=access_token, user=user)


@router.post("/register")
async def register_student(
    register_request: RegisterRequest, db=Depends(get_db)
) -> RegisterResponse:
    first_name, last_name, email, phone, password = (
        register_request.first_name.strip(),
        register_request.last_name.strip(),
        register_request.email.strip(),
        register_request.phone.strip(),
        register_request.password,
    )

    if not first_name:
        raise FirstNameRequiredException()
    if not last_name:
        raise LastNameRequiredException()
    if not email:
        raise EmailRequiredException()
    if not phone:
        raise PhoneRequiredException()
    if not password:
        raise PasswordRequiredException()

    if not is_valid_email(email):
        raise InvalidEmailFormatException()
    if not is_valid_phone(phone):
        raise InvalidPhoneFormatException()
    if not is_password_complex(password):
        raise PasswordTooWeakException()

    if is_email_taken(db, email):
        raise EmailAlreadyRegisteredException()

    hashed_password = hash_password(password)
    user = register_user(db, first_name, last_name, email, phone, hashed_password)
    email_verification_token = create_email_verification_token(db, user.id)
    await send_verification_email(user, email_verification_token)

    return RegisterResponse(email=user.email, message="Please verify email")


@router.post("/verify-email", status_code=status.HTTP_204_NO_CONTENT)
def verify_email(verification_request: VerifyEmailRequest, db=Depends(get_db)) -> None:
    if not is_valid_uuid(verification_request.verification_token):
        raise InvalidOrExpiredEmailTokenException()

    user_id = get_user_id_by_email_token(db, verification_request.verification_token)
    if not user_id:
        raise InvalidOrExpiredEmailTokenException()

    delete_email_tokens(db, user_id)
    mark_email_verified(db, user_id)


@router.post("/resend-verification", status_code=status.HTTP_204_NO_CONTENT)
async def resend_verification_email(
    resend_request: ResendVerificationMailRequest, db=Depends(get_db)
) -> None:
    if not is_valid_email(resend_request.email):
        raise InvalidEmailException()

    user = get_user_by_email(db, resend_request.email)
    if not user:
        raise EmailNotRegisteredException()

    if user.is_email_verified:
        raise EmailAlreadyVerifiedException()

    delete_email_tokens(db, user.id)
    token = create_email_verification_token(db, user.id)
    await send_verification_email(user, token)


@router.post("/refresh-token")
def refresh_token(request: Request) -> RefreshTokenResponse:
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise RefreshTokenRequiredException()

    try:
        token_data = validate_and_decode_token(refresh_token, TokenType.REFRESH)
    except JwtTokenExpiredException:
        raise InvalidOrExpiredTokenException()

    if not token_data:
        raise InvalidOrExpiredTokenException()

    access_token = create_access_token(token_data.user_id, token_data.user_role)
    return RefreshTokenResponse(access_token=access_token)


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
async def forgot_password(
    password_request: ForgotPasswordRequest, db=Depends(get_db)
) -> None:
    if not password_request.email:
        raise EmailRequiredException()
    if not is_valid_email(password_request.email):
        raise InvalidEmailFormatException()

    user = get_user_by_email(db, password_request.email)
    if not user:
        raise EmailNotRegisteredException()

    delete_password_tokens(db, user.id)
    token = create_password_reset_token(db, user.id)

    await send_reset_email(user, token)


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    reset_request: ResetPasswordRequest, db=Depends(get_db)
) -> None:
    if not reset_request.reset_token:
        raise ResetTokenRequiredException()
    if not reset_request.new_password:
        raise PasswordRequiredException()
    if not is_password_complex(reset_request.new_password):
        raise PasswordTooWeakException()

    user_id = get_user_id_by_password_token(db, reset_request.reset_token)
    if not user_id:
        raise InvalidOrExpiredResetTokenException()

    hashed_password = hash_password(reset_request.new_password)
    update_user_password(db, user_id, hashed_password)
    mark_email_verified(db, user_id)
    delete_email_tokens(db, user_id)


@router.put("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    change_request: ChangePasswordRequest,
    user_id=Depends(auth_user_id),
    db=Depends(get_db),
) -> None:
    if not change_request.old_password:
        raise PasswordRequiredException()

    if not change_request.new_password:
        raise NewPasswordRequiredException()

    if not is_password_complex(change_request.new_password):
        raise PasswordTooWeakException()

    user = get_user_by_id(db, user_id)
    if not verify_password(change_request.old_password, user.password):
        raise IncorrectOldPasswordException()

    hashed_password = hash_password(change_request.new_password)
    update_user_password(db, user_id, hashed_password)


@router.post("/admin-register", status_code=status.HTTP_204_NO_CONTENT)
async def admin_register(
    register_request: AdminRegisterUserRequest,
    db=Depends(get_db),
    roles=Security(auth_user_id_by_roles([UserRole.ADMIN])),
) -> None:
    first_name, last_name, email, phone, password, role, is_email_verified = (
        register_request.first_name.strip(),
        register_request.last_name.strip(),
        register_request.email.strip(),
        register_request.phone.strip(),
        register_request.password,
        register_request.role,
        register_request.is_email_verified,
    )

    if not first_name:
        raise FirstNameRequiredException()
    if not last_name:
        raise LastNameRequiredException()
    if not email:
        raise EmailRequiredException()
    if not phone:
        raise PhoneRequiredException()
    if not password:
        raise PasswordRequiredException()

    if not is_valid_email(email):
        raise InvalidEmailFormatException()
    if not is_valid_phone(phone):
        raise InvalidPhoneFormatException()
    if not is_password_complex(password):
        raise PasswordTooWeakException()

    if is_email_taken(db, email):
        raise EmailAlreadyRegisteredException()

    hashed_password = hash_password(password)
    user = register_user(
        db,
        first_name,
        last_name,
        email,
        phone,
        hashed_password,
        role,
        is_email_verified,
    )

    if is_email_verified:
        return

    email_verification_token = create_email_verification_token(db, user.id)
    await send_verification_email(user, email_verification_token)
