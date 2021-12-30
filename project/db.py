import click
from flask import current_app
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db():
    app = current_app
    db.init_app(app)
    app.cli.add_command(init_db_command)
    app.cli.add_command(drop_db_command)


def create_tables(app):
    '''
    Function creating tables in database.
    '''
    # import inside because of ImportError
    from project.models import Password, User
    # tables imported but unsued, there is no need to
    # use them in code
    db.create_all(app=app)


# use custom command and use it in first run (setup.sh)
@click.command('init-db')
@with_appcontext
def init_db_command():
    create_tables(current_app)
    click.echo("Tables created.")

def drop_tables(app):
    '''
    Function to drop all tables from database.
    '''
    db.drop_all(app=app)

@click.command('drop-db')
@with_appcontext
def drop_db_command():
    drop_tables(current_app)
    click.echo("Tables dropped.")