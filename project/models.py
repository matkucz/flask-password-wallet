from project.db import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(30))
    password_hash = db.Column(db.String(512))
    salt = db.Column(db.String(20), nullable=False)
    is_password_kept_as_hash = db.Column(db.Boolean, nullable=False)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    password = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    web_address = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256), nullable=False)
    login = db.Column(db.String(30), nullable=False)


class UserLogin(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    login_time = db.Column(db.DateTime, nullable=False)
    ip = db.Column(db.String(32), nullable=False)
    result = db.Column(db.Boolean, nullable=False)


class Login(db.Model):
    id = db.Column(db.Integer, primary_key = True)