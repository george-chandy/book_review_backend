from src.config import BookreviewBaseSettings


class Config(BookreviewBaseSettings):
    EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS: int
    PASSWORD_RESET_TOKEN_EXPIRY_HOURS: int
    HOST_ADDRESS: str
    JWT_ACCESS_SECRET: str
    JWT_REFRESH_SECRET: str
    JWT_ACCESS_EXPIRY_MINUTES: int
    JWT_REFRESH_EXPIRY_DAYS: int
    JWT_ISSUER: str
    JWT_AUDIENCE: str


config = Config()
