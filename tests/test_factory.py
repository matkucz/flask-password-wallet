from werkzeug.wrappers import response
from project import create_app

def test_config():
    assert not create_app().testing
    assert create_app(True).testing