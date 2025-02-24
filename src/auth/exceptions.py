from src.exceptions import BadRequest, Conflict, Unauthorized, NotFound
from src.auth.constants import ErrorCode


# TOKEN VALIDATION HTTP EXCEPTIONS
class AccessTokenRequiredException(Unauthorized):
    DETAIL = ErrorCode.ACCESS_TOKEN_REQUIRED


class InvalidAccessTokenException(Unauthorized):
    DETAIL = ErrorCode.INVALID_ACCESS_TOKEN


class AccessTokenExpiredException(Unauthorized):
    DETAIL = ErrorCode.ACCESS_TOKEN_EXPIRED


class RefreshTokenExpiredException(Unauthorized):
    DETAIL = ErrorCode.REFRESH_TOKEN_REQUIRED


# ROUTE SPECIFIC HTTP EXCEPTIONS
class EmailRequiredException(BadRequest):
    DETAIL = ErrorCode.EMAIL_REQUIRED


class PhoneRequiredException(BadRequest):
    DETAIL = ErrorCode.PHONE_REQUIRED


class PasswordRequiredException(BadRequest):
    DETAIL = ErrorCode.PASSWORD_REQUIRED


class FirstNameRequiredException(BadRequest):
    DETAIL = ErrorCode.FIRST_NAME_REQUIRED


class LastNameRequiredException(BadRequest):
    DETAIL = ErrorCode.LAST_NAME_REQUIRED


class InvalidEmailFormatException(BadRequest):
    DETAIL = ErrorCode.INVALID_EMAIL_FORMAT


class InvalidPhoneFormatException(BadRequest):
    DETAIL = ErrorCode.INVALID_PHONE_FORMAT


class PasswordTooWeakException(BadRequest):
    DETAIL = ErrorCode.PASSWORD_TOO_WEAK


class EmailAlreadyRegisteredException(Conflict):
    DETAIL = ErrorCode.EMAIL_ALREADY_REGISTERED


class InvalidOrExpiredEmailTokenException(Unauthorized):
    DETAIL = ErrorCode.INVALID_OR_EXPIRED_VERIFICATION_TOKEN


class InvalidCredentialsException(Unauthorized):
    DETAIL = ErrorCode.INVALID_CREDENTIALS


class EmailNotVerifiedException(Unauthorized):
    DETAIL = ErrorCode.EMAIL_NOT_VERIFIED


class RefreshTokenRequiredException(BadRequest):
    DETAIL = ErrorCode.REFRESH_TOKEN_REQUIRED


class InvalidOrExpiredTokenException(Unauthorized):
    DETAIL = ErrorCode.INVALID_OR_EXPIRED_TOKEN


class EmailNotRegisteredException(NotFound):
    DETAIL = ErrorCode.EMAIL_NOT_REGISTERED


class EmailAlreadyVerifiedException(BadRequest):
    DETAIL = ErrorCode.EMAIL_ALREADY_VERIFIED


class InvalidEmailException(BadRequest):
    DETAIL = ErrorCode.INVALID_EMAIL


class InvalidOrExpiredResetTokenException(Unauthorized):
    DETAIL = ErrorCode.INVALID_OR_EXPIRED_RESET_TOKEN


class ResetTokenRequiredException(BadRequest):
    DETAIL = ErrorCode.RESET_TOKEN_REQUIRED


class OldPasswordRequiredException(BadRequest):
    DETAIL = ErrorCode.OLD_PASSWORD_REQUIRED


class NewPasswordRequiredException(BadRequest):
    DETAIL = ErrorCode.NEW_PASSWORD_REQUIRED


class IncorrectOldPasswordException(BadRequest):
    DETAIL = ErrorCode.INCORRECT_OLD_PASSWORD


# Internal exceptions (Non HTTP)
class JwtTokenExpiredException(Exception): ...
