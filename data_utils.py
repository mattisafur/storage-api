from sqlalchemy.orm import Session

from models import Token, User, UserData


def user_exists(session: Session, username: str) -> bool:
    """Check if user exists in the database"""
    user = session.query(User).filter(User.username == username).one_or_none()
    return user is not None


def get_user(session: Session, username: str) -> User:
    """Get user from the database"""
    return session.query(User).filter(User.username == username).one()


def token_exists(session: Session, token: str) -> bool:
    """Check if token exists in the database"""
    token_obj = session.query(Token).filter(Token.token == token).one_or_none()
    return token_obj is not None


def get_token(session: Session, token: str) -> Token:
    """Get token from the database"""
    return session.query(Token).filter(Token.token == token).one()


def get_user_tokens(session: Session, username: str) -> list[Token]:
    """Get all user tokens from the database"""
    return session.query(Token).filter(Token.username == username).all()


def get_user_data(session: Session, username: str) -> UserData | None:
    """Get user data from the database, returns None if not found."""
    return (
        session.query(UserData).filter(UserData.username == username).one_or_none()
    )
