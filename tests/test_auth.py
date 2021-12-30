import pytest
import json


def test_register_valid(client):
    response = client.post(
        '/signup',
        headers={"Content-Type": "application/json"},
        data=json.dumps({'login': 'test', 'password': 'test', "is_hash": "true"})
    )
    assert "User account created succesfully." in response.get_json()["message"]
    assert response.status_code == 200


def test_register_already_exist(client):
    assert client.post('/signup').status_code == 401
    response = client.post(
        '/signup',
        headers={"Content-Type": "application/json"},
        data=json.dumps({'login': 'test', 'password': 'test', "is_hash": "true"})
    )
    assert "User with given name already exist" in response.get_json()["message"]
    assert response.status_code == 401


@pytest.mark.parametrize(
    ('login', 'password', 'is_hash', 'key', 'message'),
    (
        ('',     '',     '',     'login',   'Shorter than minimum length 1.'),
        ('test', '',     '',     'password','Shorter than minimum length 1.'),
        ('test', 'test', '',     'is_hash', 'Must be one of: true, false.'),
))
def test_register_empty_fields(client, login, password, is_hash, key, message):
    response = client.post(
        '/signup',
        headers={"Content-Type": "application/json"},
        data=json.dumps(
            {
                'login': login,
                'password': password,
                "is_hash": is_hash
            }
        )
    )
    assert message in response.get_json()["message"][key]
    assert response.status_code == 401


@pytest.mark.parametrize(
    ('login', 'password', 'is_hash', 'key', 'message'),
    (
        ('',     'test', '',   'login',   'Shorter than minimum length 1.'),
        ('test', '',     '',   'password','Shorter than minimum length 1.'),
        ('test', 'test', 't',  'is_hash', 'Must be one of: true, false.'),
        ('test', 'test', 'f',  'is_hash', 'Must be one of: true, false.'),
        ('test', 'test', False,'is_hash', 'Not a valid string.'),
        ('test', 'test', True, 'is_hash', 'Not a valid string.'),
))
def test_register_invalid_fields(client, login, password, is_hash, key, message):
    response = client.post(
        '/signup',
        headers={"Content-Type": "application/json"},
        data=json.dumps(
            {
                'login': login,
                'password': password,
                "is_hash": is_hash
            }
        )
    )
    assert message in response.get_json()["message"][key][0]
    assert response.status_code == 401


def test_login(client, auth):
    assert client.post('login').status_code == 401
    response = auth.login()
    assert response.status_code
    assert "access_token" in response.get_json().keys()


@pytest.mark.parametrize(
    ('login', 'password', 'key', 'message'),
    (
        ('',     '',  'login',   'Shorter than minimum length 1.'),
        ('test', '',  'password','Shorter than minimum length 1.'),
))
def test_login_empty_fields(auth, login, password, key, message):
    response = auth.login(login, password)
    assert message in response.get_json()["message"][key][0]


@pytest.mark.parametrize(
    ('login', 'password', 'key', 'message'),
    (
        ('',     '',  'login',   'Shorter than minimum length 1.'),
        ('test', '',  'password','Shorter than minimum length 1.'),
))
def test_login_invalid_fields(auth, login, password, key, message):
    response = auth.login(login, password)
    assert message in response.get_json()["message"][key][0]


def test_logout(client, auth):
    response = auth.login()
    token = response.get_json()["access_token"]
    with client:
        response = auth.logout(token)
        assert response.status_code == 200
        assert response.get_json()["message"] == "User has been logged out."

