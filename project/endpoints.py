from flask import current_app
from flask_restful import Api
from project.resources.auth_jwt import Login, Logout, Signup, Main
from project.resources.wallet_jwt import (
    ChangePassword,
    CheckPassword,
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
    api.add_resource(ChangePassword, '/passwords/change')
    api.add_resource(CheckPassword, '/passwords/check')
    api.add_resource(SharePassword, '/passwords/share')
    api.add_resource(EncryptPassword, '/passwords/encrypt/<int:password_id>')
    api.add_resource(Passwords, '/passwords')
    api.add_resource(RemoveIpBlockade, '/blockade')
    api.init_app(app)    
