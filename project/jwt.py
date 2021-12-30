from flask import current_app
from flask_jwt_extended import JWTManager

jwt = JWTManager()

def init_jwt():
# def create_jwt():
    from project.models import User
    app = current_app

    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return user.id


    @jwt.user_lookup_loader
    def user_lookup_callack(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.filter_by(id=identity).one_or_none()
    
    jwt.init_app(app)
