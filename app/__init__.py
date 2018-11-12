from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_cors import CORS

from config import config

#数据库
db = SQLAlchemy()
#登录模块
login_manage = LoginManager()
login_manage.session_protection = 'strong'

def create_app(config_name):
    #实例化app
    app = Flask(__name__)

    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    db.init_app(app)
    login_manage.init_app(app)
    CORS(app)

    # 项目启动时自动创建数据库
    with app.test_request_context():
        from .models import User,Role,Article
        db.drop_all()
        db.create_all()

        admin = Role(name='admin')
        user = Role(name='user')
        db.session.add(admin)
        db.session.add(user)
        db.session.commit()

    # 注册main组件的蓝图
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint, url_prefix='/main')
    # 注册api组件的蓝图
    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    return app
