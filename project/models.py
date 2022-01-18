from project.db import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(30))
    password_hash = db.Column(db.String(512))
    salt = db.Column(db.String(20), nullable=False)
    is_password_kept_as_hash = db.Column(db.Boolean, nullable=False)
    subseq_incorr_trials = db.Column(db.Integer, nullable=False)
    blocked = db.Column(db.Boolean, nullable=False)
    blocked_to = db.Column(db.DateTime)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    password = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    web_address = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256), nullable=False)
    login = db.Column(db.String(30), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class UserLogin(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    login_time = db.Column(db.DateTime, nullable=False)
    ip = db.Column(db.String(32), nullable=False)
    result = db.Column(db.Boolean, nullable=False)


class IpLogin(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    ip = db.Column(db.String(32), nullable=False)
    subseq_incorr_trials = db.Column(db.Integer, nullable=False)
    blocked = db.Column(db.Boolean, nullable=False)