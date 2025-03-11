from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SERVER_ADDR: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    SERVER_TEST: bool = True

    DB_USERNAME: str
    DB_PASSWORD: str
    DB_NAME: str
    DB_ADDR: str = "db"
    DB_PORT: int = 5432

    JWT_SECRET: str
    JWT_ACCESS_EXPIRE: int
    JWT_REFRESH_EXPIRE: int
    JWT_REFRESH_LONG_EXPIRE: int

    MINIMAL_PASSWORD_LENGTH: int = 8


settings = Settings()
