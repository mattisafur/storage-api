from secrets import token_urlsafe
from bcrypt import checkpw, gensalt, hashpw
from flask import Flask, request
from flask_restful import Api, Resource
from email_validator import EmailNotValidError, validate_email

from data_utils import (
    get_token,
    get_user,
    get_user_data,
    get_user_tokens,
    token_exists,
    user_exists,
)
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

        with Session() as session:
            if user_exists(session, username):
                return {"message": "User already exists"}, 409

            try:
                validate_email(email)
            except EmailNotValidError:
                return {"message": "Invalid email"}, 400

            password_hash: bytes = hash_password(password)

            user = User(username, email, password_hash)

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

        with Session() as session:
            if not user_exists(session, username):
                return {"message": "User not found"}, 404

            user = get_user(session, username)

            if not check_password(password, user.password_hash):
                return {"message": "Invalid password"}, 401

            token = Token(token_urlsafe(Token.TOKEN_LENGTH), user.username)

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

        with Session() as session:
            if not token_exists(session, token):
                return {"message": "Token not found"}, 404

            token_obj = get_token(session, token)
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

        with Session() as session:
            if not user_exists(session, username):
                return {"message": "User not found"}, 404

            user = get_user(session, username)

            if not check_password(password, user.password_hash):
                return {"message": "Invalid password"}, 401

            # delete all user tokens
            for token in get_user_tokens(session, username):
                session.delete(token)
            session.commit()

            # delete user data
            user_data = get_user_data(session, user.username)
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

        with Session() as session:
            if not token_exists(session, token):
                return {"message": "Token not found"}, 404

            token_obj = get_token(session, token)

            data = get_user_data(session, token_obj.username)

        if data is None:
            return {"message": "No user data"}, 404

        return {"data": data.data}, 200

    def post(self):
        request_data = request.json
        if request_data is None:
            return {"message": "No data provided"}, 400

        token: str = request_data["token"]
        data: str = request_data["data"]

        with Session() as session:
            if not token_exists(session, token):
                return {"message": "Token not found"}, 404

            token_obj = get_token(session, token)

            data_obj = get_user_data(session, token_obj.username)

            if data_obj is None:
                data_obj = UserData(token_obj.username, data)
            else:
                data_obj.data = data
            session.add(data_obj)
            session.commit()

        return {"message": "User data updated successfully"}, 200


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
