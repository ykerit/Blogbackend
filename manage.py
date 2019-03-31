from app import create_app
from flask_script import Manager


app = create_app('production')
manager = Manager(app)


@app.route('/')
def hello():
    return 'api 1.0'


if __name__ == '__main__':
    manager.run()
