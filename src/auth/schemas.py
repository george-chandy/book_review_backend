from enum import Enum
from pydantic import BaseModel, ConfigDict


class User(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    phone: str

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    user: User


class RegisterRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone: str
    password: str


class RegisterResponse(BaseModel):
    email: str
    message: str


class VerifyEmailRequest(BaseModel):
    verification_token: str


class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"


class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"


class TokenData(BaseModel):
    user_id: int
    user_role: UserRole


class RefreshTokenResponse(BaseModel):
    access_token: str


class ResendVerificationMailRequest(BaseModel):
    email: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class AdminRegisterUserRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone: str
    password: str
    role: UserRole
    is_email_verified: bool
