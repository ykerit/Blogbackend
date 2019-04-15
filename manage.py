from app import create_app
from flask_script import Manager


app = create_app('default')
manager = Manager(app)


@app.route('/')
def hello():
    return 'api 1.2.6'


if __name__ == '__main__':
    manager.run()
