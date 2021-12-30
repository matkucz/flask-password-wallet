# Python password wallet
Password wallet written in Flask with Postgres as Database.

## HOW TO SETUP THIS PROJECT
Install dependencies from requirements.txt.
In main directory create setup.py file and .env file.
In setup file you need two classes: DevConfig and TestConfig.

### .env file example
```
HASH_PEPPER="<your_random_hash_paper>"
FLASK_ENV=development
FLASK_APP="project"
```
### Setup.py file example
```
class DevConfig(object):
    # database settings
    SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://<db_username>:<db_password>@<db_host>:<db_port>/<db_name>"
    # flask settings
    SECRET_KEY="<secret_key>"
    DEBUG = True
    DEVELOPMENT = True
    # jwt settings
    JWT_SECRET_KEY = "<jwt_secret_key>"
    # sqlalchemy settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True

class TestConfig(object):
    '''
    Testing configuration.
    '''
    # database settings
    SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://<db_username>:<db_password>@<db_host>:<db_port>/<db_name>"
    # flask settings
    SECRET_KEY="<test_secret_key>"
    DEBUG = False
    TESTING = True
    # jwt settings
    JWT_SECRET_KEY = "<test_jwt_secret_key>"
    # sqlalchemy settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
```

To run server, run *flask run* in terminal.
To run tests, run *pytest* in terminal.