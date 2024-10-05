from datetime import datetime, timedelta
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, declarative_base, mapped_column
from sqlalchemy.dialects.postgresql import CITEXT

Base = declarative_base()


class User(Base):
    __tablename__: str = "users"

    # username - primary key, case insensitive, alphanumeric (constrained in __table_args__)
    # email - unique, case insensitive
    # password - salted and hashed
    username: Mapped[str] = mapped_column(CITEXT, primary_key=True)
    email: Mapped[str] = mapped_column(CITEXT, unique=True)
    password_hash: Mapped[bytes]

    __table_args__ = (
        CheckConstraint(
            "username ~ '^[a-zA-Z0-9]+$'", name="check_username_alphanumeric"
        ),
        # ? should the email be validated in the DB as well?
    )

    def __init__(self, username: str, email: str, password_hash: bytes) -> None:
        self.username = username
        self.email = email
        self.password_hash = password_hash

    def __repr__(self) -> str:
        return f"<User(username: {self.username}, email: {self.email})>"


class Token(Base):
    __tablename__: str = "tokens"

    TOKEN_VALIDITY_DURATION_SEC: int = 3600
    TOKEN_LENGTH: int = 32

    # token - primary key
    # username - foreign key
    # created_at - supports timezones
    # expires_at - supports timezones
    token: Mapped[str] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(ForeignKey("users.username"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now() # pylint: disable=E1102
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now() + timedelta(seconds=TOKEN_VALIDITY_DURATION_SEC), # pylint: disable=E1102
    )

    def __init__(self, token: str, username: str) -> None:
        self.token = token
        self.username = username

    def __repr__(self) -> str:
        return f"<Token(token: {self.token}, username: {self.username}, created_at: {self.created_at}, expires_at: {self.expires_at})>"


class UserData(Base):
    __tablename__: str = "user_data"

    # username - primary key, foreign key
    # data - string
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username"), primary_key=True
    )
    data: Mapped[str]

    def __init__(self, username: str, data: str) -> None:
        self.username = username
        self.data = data

    def __repr__(self) -> str:
        return f"<UserData(username: {self.username}, data: {self.data})>"
