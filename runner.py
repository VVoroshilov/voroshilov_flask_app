import os
from app import app, db
from flask_script import Manager, Shell

manager = Manager(app)

def make_shell_context():
    return dict(app=app, db=db)

manager.add_command('shell', Shell(make_context=make_shell_context))

if __name__ == '__main__':
    manager.run()