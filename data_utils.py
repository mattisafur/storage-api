from database import Session
from models import Token, User, UserData


def user_exists(username: str) -> bool:
    """Check if user exists in the database"""
    with Session() as session:
        user = session.query(User).filter(User.username == username).one_or_none()
        return user is not None


def get_user(username: str) -> User:
    """Get user from the database"""
    with Session() as session:
        return session.query(User).filter(User.username == username).one()


def token_exists(token: str) -> bool:
    """Check if token exists in the database"""
    with Session() as session:
        token_obj = session.query(Token).filter(Token.token == token).one_or_none()
        return token_obj is not None


def get_token(token: str) -> Token:
    """Get token from the database"""
    with Session() as session:
        return session.query(Token).filter(Token.token == token).one()


def get_user_tokens(username: str) -> list[Token]:
    """Get all user tokens from the database"""
    with Session() as session:
        return session.query(Token).filter(Token.username == username).all()


def get_user_data(username: str) -> UserData | None:
    """Get user data from the database, returns None if not found."""
    with Session() as session:
        return (
            session.query(UserData).filter(UserData.username == username).one_or_none()
        )
