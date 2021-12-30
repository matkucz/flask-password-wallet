import json
import pytest
from project import create_app
from project.db import db, create_tables, drop_tables
from project.models import User, Password
# TODO: setup database before tests and drop after
# before tests setup tables and insert one row
# https://stackoverflow.com/questions/22627659/run-code-before-and-after-each-test-in-py-test
# flask testing
# https://medium.com/analytics-vidhya/how-to-test-flask-applications-aef12ae5181c


class AuthActions(object):
    def __init__(self, client):
        self._client = client

    def login(self, login='test', password='test'):
        return self._client.post(
            '/login',
            headers={"Content-Type": "application/json"},
            data=json.dumps({"login": login, "password": password})
        )

    def logout(self, token):
        return self._client.post(
            '/logout', headers={"Authorization": f"Bearer {token}"}
        )

class PasswordActions(object):
    def __init__(self, client):
        self._client = client

    def login(self, login='test', password='test'):
        return self._client.post(
            '/login',
            headers={"Content-Type": "application/json"},
            data=json.dumps({"login": login, "password": password})
        )

    def logout(self, token):
        return self._client.post(
            '/logout', headers={"Authorization": f"Bearer {token}"}
        )
    
    def get_passwords(self, token):
        return self._client.get(
            '/passwords', headers={"Authorization": f"Bearer {token}"}
        )
    
    def check_master_password(self, token, password='test'):
        return self._client.get(
            '/passwords/check',
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            },
            data=json.dumps({"password": password})
        )

    def encrypt_password(self, token, row_number=0):
        return self._client.get(
            f'/passwords/encrypt/{row_number}',
            headers={"Authorization": f"Bearer {token}"}
        )
        
@pytest.fixture(scope="session")
def app():
    app = create_app(True)
    with app.app_context():
        # create tables before tests
        create_tables(app)
    yield app
    # drop tables after tests
    drop_tables(app)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


@pytest.fixture
def auth(client):
    return AuthActions(client)


@pytest.fixture
def wallet(client):
    return PasswordActions(client)
