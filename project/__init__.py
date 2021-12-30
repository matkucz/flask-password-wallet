from flask import Flask

def create_app(test_config=False):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    # get app variables from environment
    if test_config == True:
        app.config.from_object('config.TestConfig')
    else:
        app.config.from_object('config.DevConfig')

    from project.db import init_db
    from project.jwt import init_jwt
    from project.endpoints import init_api
    from project.schemas import init_schema
    with app.app_context():
        init_db()
        init_api()
        init_jwt()
    return app
