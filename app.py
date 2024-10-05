from secrets import token_urlsafe
from bcrypt import checkpw, gensalt, hashpw
from flask import Flask, request
from flask_restful import Api, Resource
from email_validator import EmailNotValidError, validate_email

from models import Base, Token, User, UserData
from database import Session, engine


app = Flask(__name__)
api = Api(app)


class Register(Resource):
    def post(self):
        request_data = request.json
        if request_data is None:
            return {"message": "No data provided"}, 400

        username: str = request_data["username"]
        email: str = request_data["email"]
        password: str = request_data["password"]

        if user_exists(username):
            return {"message": "User already exists"}, 409

        try:
            validate_email(email)
        except EmailNotValidError:
            return {"message": "Invalid email"}, 400

        password_hash: bytes = hash_password(password)

        user = User(username, email, password_hash)

        with Session() as session:
            session.add(user)
            session.commit()

        return {"message": "User created successfully"}, 201


class Login(Resource):
    def post(self):
        request_data = request.json
        if request_data is None:
            return {"message": "No data provided"}, 400

        username: str = request_data["username"]
        password: str = request_data["password"]

        if not user_exists(username):
            return {"message": "User not found"}, 404

        user = get_user(username)

        if not check_password(password, user.password_hash):
            return {"message": "Invalid password"}, 401

        token = Token(token_urlsafe(Token.TOKEN_LENGTH), user.username)

        with Session() as session:
            session.add(token)
            session.commit()

            return {
                "token": token.token,
                "expires_at": token.expires_at.isoformat(),
            }, 201


class LogOut(Resource):
    def post(self):
        request_data = request.json
        if request_data is None:
            return {"message": "No data provided"}, 400

        token: str = request_data["token"]

        if not token_exists(token):
            return {"message": "Token not found"}, 404

        token_obj = get_token(token)
        with Session() as session:
            session.delete(token_obj)
            session.commit()

        return {"message": "Token deleted successfully"}, 200


class Delete(Resource):
    def delete(self):
        request_data = request.json
        if request_data is None:
            return {"message": "No data provided"}, 400

        username: str = request_data["username"]
        password: str = request_data["password"]

        if not user_exists(username):
            return {"message": "User not found"}, 404

        user = get_user(username)

        if not check_password(password, user.password_hash):
            return {"message": "Invalid password"}, 401

        with Session() as session:
            # delete all user tokens
            for token in get_user_tokens(username):
                session.delete(token)
            session.commit()

            # delete user data
            user_data = get_user_data(user.username)
            if user_data is not None:
                session.delete(user_data)
                session.commit()

            # delete user
            session.delete(user)
            session.commit()

        return {"message": "User deleted successfully"}, 200


class Data(Resource):
    def get(self):
        request_data = request.json
        if request_data is None:
            return {"message": "No data provided"}, 400

        token: str = request_data["token"]

        if not token_exists(token):
            return {"message": "Token not found"}, 404

        token_obj = get_token(token)

        data = get_user_data(token_obj.username)
        if data is None:
            return {"message": "No user data"}, 404

        return {"data": data.data}, 200

    def post(self):
        request_data = request.json
        if request_data is None:
            return {"message": "No data provided"}, 400

        token: str = request_data["token"]
        data: str = request_data["data"]

        if not token_exists(token):
            return {"message": "Token not found"}, 404

        token_obj = get_token(token)

        data_obj = get_user_data(token_obj.username)

        with Session() as session:
            if data_obj is None:
                data_obj = UserData(token_obj.username, data)
            else:
                data_obj.data = data
            session.add(data_obj)
            session.commit()

        return {"message": "User data updated successfully"}, 200


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


def hash_password(passsword: str) -> bytes:
    """Hashes password"""
    return hashpw(passsword.encode(), gensalt())


def check_password(password: str, password_hash: bytes) -> bool:
    """Check if password matches hash"""
    return checkpw(password.encode(), password_hash)


if __name__ == "__main__":
    Base.metadata.create_all(engine)

    api.add_resource(Register, "/register")
    api.add_resource(Login, "/login")
    api.add_resource(LogOut, "/logout")
    api.add_resource(Delete, "/delete")
    api.add_resource(Data, "/data")

    app.run(debug=True)
