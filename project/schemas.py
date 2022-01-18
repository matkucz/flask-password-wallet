from importlib.metadata import requires
from flask import current_app
from flask_marshmallow import Marshmallow
from marshmallow import fields, validate
ma = Marshmallow()

def init_schema():
    app = current_app
    ma.init_app(app)

RequiredNonEmptyString = fields.Str(
    required=True,
    validate=validate.Length(min=1)
)


class LoginSchema(ma.Schema):
    login = RequiredNonEmptyString
    password = RequiredNonEmptyString


class SignupSchema(ma.Schema):
    login = RequiredNonEmptyString
    password = RequiredNonEmptyString
    is_hash = fields.Bool(
        required=True
    )


class PasswordSchema(ma.Schema):
    login = RequiredNonEmptyString    
    password = RequiredNonEmptyString
    web_address = fields.URL(required=True)
    description = RequiredNonEmptyString


class ChangePasswordSchema(ma.Schema):
    password = RequiredNonEmptyString
    password2 = RequiredNonEmptyString
    new_password = RequiredNonEmptyString


class CheckPasswordSchema(ma.Schema):
    password = RequiredNonEmptyString


class SharePasswordShema(ma.Schema):
    id = fields.Int(
        required=True
    )
    login = RequiredNonEmptyString