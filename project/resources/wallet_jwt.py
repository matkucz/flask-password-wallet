from os import getenv
from flask_restful import Resource
from flask import request
from flask_jwt_extended import jwt_required, current_user
from marshmallow import ValidationError
from project.db import db
from project.models import Password, IpLogin, User
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
    SharePasswordShema
)

class Passwords(Resource):
    @jwt_required()
    def get(self):
        """
        Get all user passwords.
        """
        passwords = Password.query.filter_by(
                user_id=current_user.id
            ).order_by(Password.id).all()
        result_list = [{
            "id": password.id, 
            "password": password.password, 
            "user_id": password.user_id, 
            "web_address": password.web_address, 
            "description": password.description, 
            "login": password.login,
            "is_owner": password.owner_id == current_user.id,            

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
            login=login,
            owner_id=current_user.id
        )
        # save data to database
        db.session.add(new_password)
        db.session.commit()
        return {
            "message": "Password was succesfully added."
        }


class EditOrDelPassword(Resource):
    @jwt_required()
    def put(self, id):
        password = Password.query.filter_by(id=id).one_or_none()
        json = request.get_json()
        try:
            if password.owner_id != current_user.id:
                return {
                    "message": "Only owner can change the password."
                }, 401
            new_password = json["password"]
            # generate key
            key = generate_key(current_user.password_hash)
            # encrypt password with generated key
            encrypted = encrypt(new_password, key)
            password.login = json["login"]
            password.password = encrypted
            password.description = json["description"]
            password.web_address = json["web_address"]
            db.session.add(password)
            db.session.commit()
            return {
                "message": "Password edited."
            }
        except AttributeError:
            return {
                "message": "Invalid data."
            }, 401

    @jwt_required()
    def delete(self, id):
        password = Password.query.filter_by(id=id).one_or_none()
        try:
            if password.owner_id != current_user.id:
                return {
                    "message": "Only owner can change the password."
                }, 401
            db.session.delete(password)
            db.session.commit()
            return {
                "message": "Password deleted."
            }
        except AttributeError:
            return {
                "message": "Invalid data."
            }, 401
        

class CheckMasterPassword(Resource):
    @jwt_required()
    def post(self):
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

class ChangeMasterPassword(Resource):
    @jwt_required()
    def put(self):
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
            # check if user is owner of password
            if password.owner_id == current_user.id:
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
    def get(self, password_id):
        # get all passwords for user from database
        password = Password.query.filter_by(
            id=password_id
        ).one_or_none()
        try:
            encrypted_password = password.password
            password_hash = current_user.password_hash
            if password.owner_id != current_user.id:
                pepper = str(getenv("HASH_PEPPER"))
                salt = str(getenv("SHARING_SALT"))
                password_hash = calculate_sha512(salt + pepper)
            key = generate_key(password_hash)
            # decrypt password
            decrypted_password = decrypt(encrypted_password, key)
            return {
                "data": decrypted_password.decode("utf-8")
            }
        except AttributeError as error:
            return {
                "message": "Password doesn't exists."
            }, 401    


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


class SharePassword(Resource):
    @jwt_required()
    def post(self):
        """
        Add shared password to another user.
        """
        # get data from form
        request_json = request.get_json()
        if request_json is None:
            return {
                "message": "No data send."
            }, 401
        schema = SharePasswordShema()    
        try:
            schema.load(request.get_json())
        except ValidationError as error:
            return {"message": error.messages}, 401        
        password_id = request_json["id"]
        login = request_json["login"]
        # get shared password
        password = Password.query.filter_by(
            id=password_id
        ).one_or_none()
        # check if owner is sharing password
        if password.owner_id != current_user.id:
            return {
                "message": "You have to be owner to share password."
            }, 401
        # get user
        user = User.query.filter_by(login=login).one_or_none()             
        # check if password isn't shared to owner
        if user.id == current_user.id:
            return {
                "message": "You can't share password to yourself."
            }, 401
        encrypted_password = password.password
        old_key = generate_key(current_user.password_hash)
        # decrypt password
        decrypted_password = decrypt(encrypted_password, old_key)
        # generate new key (sharing one, same for all users)
        pepper = str(getenv("HASH_PEPPER"))
        salt = str(getenv("SHARING_SALT"))
        password_hash = calculate_sha512(salt + pepper)
        new_key = generate_key(password_hash)
        # encrypt password with new sharing key
        encrypted = encrypt(decrypted_password.decode("utf-8"), new_key)
        try:
            new_password = Password(
                user_id=user.id,
                password=encrypted,
                web_address=password.web_address,
                description=password.description,
                login=password.login,
                owner_id=current_user.id
            )
            # save data to database
            db.session.add(new_password)
            db.session.commit()
            return {
                "message": "Password was succesfully shared."
            }
        except (AttributeError):
            return {
                "messsage": "User with given login doesn't exist"
            }, 401