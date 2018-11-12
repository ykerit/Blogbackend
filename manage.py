import os
from app import create_app, db
#from app.models import Post
from flask_script import Manager, Server
# from flask_migrate import Migrate, MigrateCommand


app = create_app('default')
manager = Manager(app)


'''
#migrate = Migrate(app, db)
def make_shell_context():
    return dict(app=app, db=db, Post=Post)
manager.add_command("shell", Shell(make_context=make_shell_context))
#manager.add_command('db', MigrateCommand)
'''


@app.route('/')
def hello():
    return 'api 0.1'


if __name__ == '__main__':
    manager.run()