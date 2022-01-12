from os import getenv
from flask_restful import Resource
from flask import request
from flask_jwt_extended import jwt_required, current_user
from marshmallow import ValidationError
from project.db import db
from project.models import Password, IpLogin
from project.cipher import (
    decrypt,
    encrypt,
    generate_key
)
from project.hash import (
    verify_hashed_text,
    generate_random_string,
    calculate_sha512,
    calculate_hmac
)
from project.schemas import (
    CheckPasswordSchema,
    ChangePasswordSchema,
    PasswordSchema, 
)

class Passwords(Resource):
    @jwt_required()
    def get(self):
        """
        Get all user passwords.
        """
        passwords = Password.query.filter_by(user_id=current_user.id).all()
        result_list = [{
            "id": password.id, 
            "password": password.password, 
            "user_id": password.user_id, 
            "web_address": password.web_address, 
            "description": password.description, 
            "login": password.login, 

        } for password in passwords]
        return {
            "data": result_list
        }



    @jwt_required()
    def post(self):
        """
        Add new password.
        """
        # get data from form
        request_json = request.get_json()
        if request_json is None:
            return {
                "message": "No data send."
            }, 401
        schema = PasswordSchema()
        # can use schema.validate()
        # https://marshmallow.readthedocs.io/en/stable/quickstart.html#validation-without-deserialization
        try:
            schema.load(request.get_json())
        except ValidationError as error:
            return {"message": error.messages}, 401
        password = request_json["password"]
        web_address = request_json["web_address"]
        description = request_json["description"]
        login = request_json["login"]
        # generate key
        key = generate_key(current_user.password_hash)
        # encrypt password with generated key
        encrypted = encrypt(password, key)
        new_password = Password(
            user_id=current_user.id,
            password=encrypted,
            web_address=web_address,
            description=description,
            login=login
        )
        # save data to database
        db.session.add(new_password)
        db.session.commit()
        return {
            "message": "Password was succesfully added."
        }

class CheckPassword(Resource):
    @jwt_required()
    def get(self):
        request_json = request.get_json()
        schema = CheckPasswordSchema()
        # can use schema.validate()
        # https://marshmallow.readthedocs.io/en/stable/quickstart.html#validation-without-deserialization
        try:
            schema.load(request_json)
        except ValidationError as error:
            return {"message": error.messages}, 401
        password = request_json["password"]
        password_hash = current_user.password_hash
        is_hash = current_user.is_password_kept_as_hash
        salt = current_user.salt
        try:
            verify_hashed_text(
                password, salt, password_hash, is_hash
            )
        except (AttributeError, ValueError):
            return {
                "message": "Please insert correct master password."
            }, 401 
        return {
            "message": "Succesfull master password validation."
        }

class ChangePassword(Resource):
    @jwt_required()
    def patch(self):
        # get data from form
        request_json = request.get_json()
        schema = ChangePasswordSchema()
        # can use schema.validate()
        # https://marshmallow.readthedocs.io/en/stable/quickstart.html#validation-without-deserialization
        try:
            schema.load(request_json)
        except ValidationError as error:
            return {"message": error.messages}, 401
        old_pass = request_json["password"]
        old_pass_2 = request_json["password2"]
        new_password = request_json["new_password"]
        # compare passwords from form
        if old_pass != old_pass_2:
            return {
                "message": "Old passwords are not the same."
            }, 401
        # compare passwords from form
        if old_pass == new_password:
            return {
                "message": "Old and new password should not be same."
            }, 401
        # generate new salt
        salt = generate_random_string(size=20)
        password_hash = ""
        old_password_hash = ""
        if current_user.is_password_kept_as_hash:
            pepper = str(getenv("HASH_PEPPER"))
            password_hash = calculate_sha512(new_password + salt + pepper)
            # calculate hash for old pass from form with old salt
            old_password_hash = calculate_sha512(old_pass + current_user.salt + pepper)
        else:
            password_hash = calculate_hmac(new_password, salt)
            # calculate hash for old pass from form with old salt
            old_password_hash = calculate_hmac(old_pass, current_user.salt)
        # compare hashes, one from form and one from database
        if old_password_hash != current_user.password_hash:
            return {
                "message": "Wrong old master password, please check and try again."
            }, 401
        # get encrypted passwords for given user
        passwords = Password.query.filter_by(user_id=current_user.id)
        # generate old and new key
        old_key = generate_key(current_user.password_hash)
        key = generate_key(password_hash)
        # decrypt passwords with old key and encrypt with new
        for password in passwords:
            decrypted_password = decrypt(password.password, old_key)
            encrypted = encrypt(decrypted_password.decode("utf-8"), key)
            password.password = encrypted
            db.session.add(password)


        current_user.password_hash = password_hash
        current_user.salt = salt
        # save changes in database
        db.session.add(current_user)
        db.session.commit()
        return {
            "message": "Master password changed succesfully."
        }

class EncryptPassword(Resource):
    @jwt_required()
    def get(self, row_number):
        # get all passwords for user from database
        passwords = Password.query.filter_by(
            user_id=current_user.id
        ).all()
        if not 0 <= row_number < len(passwords):
            return {
                "message": "Invalid row number."
            }
        # get password with given row number (from web page)
        encrypted_password = passwords[row_number].password
        key = generate_key(current_user.password_hash)
        # decrypt password
        decrypted_password = decrypt(encrypted_password, key)
        return {
            "data": decrypted_password.decode("utf-8")
        }


class RemoveIpBlockade(Resource):
    @jwt_required()
    def post(self):
        request_json = request.get_json()
        ip_address = request_json["ip_address"]
        ip_login = IpLogin.query.filter_by(ip=ip_address).one_or_none()
        try:
            ip_login.blocked = False
            ip_login.subseq_incorr_trials = 0
        except AttributeError as atrr_error:
            return {
                "message": "No such IP address"
            }, 401
        db.session.add(ip_login)
        db.session.commit()
        return {
            "message": "IP address blockade removed"
        }, 401