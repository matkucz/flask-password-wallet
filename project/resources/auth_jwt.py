from functools import wraps
from os import getenv
from flask import request
from flask_jwt_extended import jwt_required, create_access_token
from flask_restful import Resource
from marshmallow import ValidationError, validates_schema
from project.db import db
from project.jwt import jwt
from project.hash import (
    calculate_hmac,
    calculate_sha512,
    generate_random_string,
    verify_hashed_text
)
from project.models import User
from project.schemas import LoginSchema, SignupSchema

def validate(func):
    @wraps(func)
    def wrapper(**kwargs):
        request_json = request.get_json()
        print(**kwargs)
        if  request_json is None:
            return {
                "message": "No data send."
            }, 401
    return wrapper        

class Login(Resource):
    method_decorators = [validate]

    @validates_schema(LoginSchema)
    def post(self):
        schema = LoginSchema()
        # can use schema.validate()
        # https://marshmallow.readthedocs.io/en/stable/quickstart.html#validation-without-deserialization
        try:
            schema.load(request.get_json())
        except ValidationError as error:
            return {"message": error.messages}, 401
        login = request.json.get("login")
        password = request.json.get("password")
        user = User.query.filter_by(login=login).one_or_none()
        try:
            is_hash = user.is_password_kept_as_hash
            salt = user.salt
            password_hash = user.password_hash
            verify_hashed_text(password, salt, password_hash, is_hash)
        except (AttributeError, ValueError) as verify_errors:
            return {
                "message": "Please check your login details and try again."
            }, 401
        token = create_access_token(identity=user)
        return {
            "access_token": token
        }

class Signup(Resource):
    def post(self):
        request_json = request.get_json()
        if request_json is None:
            return {
                "message": "No data send."
            }, 401
        schema = SignupSchema()
        try:
            schema.load(request.get_json())
        except ValidationError as error:
            return {"message": error.messages}, 401
        login = request_json["login"]
        password = request_json["password"]
        is_hash =  True if request_json["is_hash"] == "true" else False
        salt = generate_random_string(size=20)
        password_hash = ""
        if is_hash:
            pepper = str(getenv("HASH_PEPPER"))
            password_hash = calculate_sha512(password + salt + pepper)
        else:
            password_hash = calculate_hmac(password, salt)
        user = User.query.filter_by(login=login).first()
        if user:
            return {
                    "message": "User with given name already exist."
            }, 401

        new_user = User(
            login=login,
            password_hash=password_hash,
            salt=salt,
            is_password_kept_as_hash=is_hash
        )
        db.session.add(new_user)
        db.session.commit()
        return {
            "message": "User account created succesfully."
        }


class Logout(Resource):
    """

    """
    @jwt_required()
    def post(self):
        """
    
        """
        return {
            "message": "User has been logged out."
        }

class Main(Resource):
    def get(self):
        print(request.headers, request.access_route, request.remote_addr)
        return "Twój adres ip to: " + request.remote_addr