from app import create_app, db
from flask_script import Manager
# from flask_migrate import Migrate, MigrateCommand


app = create_app('default')
manager = Manager(app)


# migrate = Migrate(app, db)
# manager.add_command('db', MigrateCommand)


@app.route('/')
def hello():
    return 'api 1.0'


if __name__ == '__main__':
    manager.run()
