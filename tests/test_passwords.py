import json
import pytest

def test_password(client, wallet):
    assert client.get('/passwords').status_code == 401
    response = wallet.login()
    token = response.get_json()["access_token"]
    result = wallet.get_passwords(token).get_json()["data"]
    assert result == []


@pytest.mark.parametrize(
    ('password', 'web_address', 'description', 'login', 'key', 'message'),
    (
        ('',     '',     '',     '', 'password',    'Shorter than minimum length 1.'),
        ('test', '',     '',     '', 'web_address', 'Not a valid URL'),
        ('test', 'test', '',     '', 'description', 'Shorter than minimum length 1.'),
        ('test', 'test', 'test', '', 'login',       'Shorter than minimum length 1.'),
))
def test_post_passwords_validate_input(
    client, password, web_address, description, login, key, message
):
    token = client.post(
        '/login', 
        headers={"Content-Type": "application/json"}, 
        data=json.dumps({"login": "test", "password": "test"})
    ).get_json()["access_token"]
    response = client.post(
        '/passwords', 
        headers={
            "Content-Type": "application/json", 
            "Authorization": f"Bearer {token}"
        }, 
        data=json.dumps(
            {
                'password': password, 
                'web_address': web_address,
                "description": description,
                "login": login
            }
        )
    )
    assert message in response.get_json()["message"][key][0]


@pytest.mark.parametrize(
    ('password', 'web_address', 'description', 'login', 'message'),
    (
        (
            'test', 
            'http://test.pl', 
            'Haslo do konta na stronie', 
            'test', 
            'Password was succesfully added.'
        ),
))
def test_post_passowords_correct_passwords(
     client, password, web_address, description, login, message
):
    token = client.post(
        '/login', 
        headers={"Content-Type": "application/json"}, 
        data=json.dumps({"login": "test", "password": "test"})
    ).get_json()["access_token"]
    response = client.post(
        '/passwords', 
        headers={
            "Content-Type": "application/json", 
            "Authorization": f"Bearer {token}"
        }, 
        data=json.dumps(
            {
                'password': password, 
                'web_address': web_address,
                "description": description,
                "login": login
            }
        )
    )
    assert message in response.get_json()["message"]


def test_master_password_check(client, wallet):
    assert client.get('/passwords').status_code == 401
    response = wallet.login()
    token = response.get_json()["access_token"]
    result = wallet.check_master_password(token).get_json()["message"]
    assert result == "Succesfull master password validation."


@pytest.mark.parametrize(
    ('password', 'message'),
    (
        ('zle_haslo', 'Please insert correct master password.'),
))
def test_post_passwords_invalid_password(
    client, password, message
):
    token = client.post(
        '/login', 
        headers={"Content-Type": "application/json"}, 
        data=json.dumps({"login": "test", "password": "test"})
    ).get_json()["access_token"]
    response = client.get(
        '/passwords/check', 
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, 
        data=json.dumps(
            {
                'password': password,
            }
        )
    )
    assert message in response.get_json()["message"]


@pytest.mark.parametrize(
    ('password', 'message'),
    (
        ('', 'Shorter than minimum length 1.'),
))
def test_post_passwords_empty_password(
    client, password, message
):
    token = client.post(
        '/login', 
        headers={"Content-Type": "application/json"}, 
        data=json.dumps({"login": "test", "password": "test"})
    ).get_json()["access_token"]
    response = client.get(
        '/passwords/check', 
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, 
        data=json.dumps(
            {
                'password': password,
            }
        )
    )
    assert message in response.get_json()["message"]["password"]


def test_encrypt_password_valid_row_number(client, wallet):
    assert client.get('/passwords/encrypt/1').status_code == 401
    response = wallet.login()
    token = response.get_json()["access_token"]
    result = wallet.encrypt_password(token, 0).get_json()
    assert 'data' in result.keys()


def test_encrypt_password_invalid_row_number(client, wallet):
    assert client.get('/passwords/encrypt/0').status_code == 401
    response = wallet.login()
    token = response.get_json()["access_token"]
    result = wallet.encrypt_password(token, 1).get_json()["message"]
    assert result == "Invalid row number."