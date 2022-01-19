from datetime import date, datetime, timedelta
from functools import wraps
from os import getenv
import time
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
from project.models import User, UserLogin, IpLogin
from project.schemas import LoginSchema, SignupSchema
     

class Login(Resource):
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
        ip_address = request.remote_addr
        ip_login = IpLogin.query.filter_by(ip=ip_address).one_or_none()
        user_login = UserLogin(
            login_time=datetime.now(),         
            ip=ip_address
        )
        if ip_login is not None:
            if ip_login.blocked:
                return {
                    "message": "Your IP address is permamently blocked."
                }, 401
        else:
            ip_login = IpLogin(
                ip = ip_address,
                subseq_incorr_trials = 0,
                blocked = False
            )
        if user is not None:
            if datetime.now() < user.blocked_to:
                return {
                    "message": "Your account is blocked, try again later."
                }, 401
        try:
            is_hash = user.is_password_kept_as_hash
            salt = user.salt
            password_hash = user.password_hash
            verify_hashed_text(password, salt, password_hash, is_hash)
        except AttributeError as atrr_error:            
            return {
                "message": "Please check your login details and try again."
            }, 401
        except ValueError as verify_errors:
            user_login.result = False
            user.subseq_incorr_trials = user.subseq_incorr_trials + 1
            ip_login.subseq_incorr_trials = ip_login.subseq_incorr_trials + 1
            # when account exists
            user_login.user_id = user.id
            if user.subseq_incorr_trials == 2 or ip_login.subseq_incorr_trials == 2:
                time.sleep(5)
            if user.subseq_incorr_trials == 3 or ip_login.subseq_incorr_trials == 3:
                time.sleep(10)
            if user.subseq_incorr_trials >= 4:
                user.blocked = True
                user.blocked_to = datetime.now() + timedelta(minutes=2)
            if ip_login.subseq_incorr_trials > 4:
                ip_login.blocked = True
            db.session.add(user_login)
            db.session.add(user)
            db.session.add(ip_login)
            db.session.commit()
            return {
                "message": "Please check your login details and try again."
                if not user.blocked
                else "Your account have been blocked, try again later."
            }, 401
        user_login.user_id = user.id
        user_login.result = True
        user.subseq_incorr_trials = 0
        ip_login.subseq_incorr_trials = 0
        db.session.add(user_login)
        db.session.add(user)
        db.session.add(ip_login)
        db.session.commit()
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
        is_hash = request_json["is_hash"]
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
            is_password_kept_as_hash=is_hash,
            subseq_incorr_trials = 0,
            blocked=False,
            blocked_to=datetime.now(),
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
    @jwt_required()
    def get(self):
        return {
            "message": "Token is valid"
        }