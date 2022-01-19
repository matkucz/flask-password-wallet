from flask import current_app
from flask_restful import Api
from project.resources.auth_jwt import Login, Logout, Signup, Main
from project.resources.wallet_jwt import (
    ChangeMasterPassword,
    CheckMasterPassword,
    EditOrDelPassword,
    EncryptPassword,
    Passwords,
    RemoveIpBlockade,
    SharePassword
)


def init_api():  
# def create_api():
    api = Api()
    app = current_app
    api.add_resource(Main, '/')
    api.add_resource(Login, '/login')
    api.add_resource(Logout, '/logout')
    api.add_resource(Signup, '/signup')
    api.add_resource(ChangeMasterPassword, '/master')
    api.add_resource(CheckMasterPassword, '/master/check')
    api.add_resource(SharePassword, '/passwords/share')
    api.add_resource(EncryptPassword, '/passwords/encrypt/<int:password_id>')
    api.add_resource(Passwords, '/passwords')
    api.add_resource(EditOrDelPassword, '/passwords/<int:id>')
    api.add_resource(RemoveIpBlockade, '/blockade')
    api.init_app(app)    
