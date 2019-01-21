from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

from config import config

# 数据库
db = SQLAlchemy()


def create_app(config_name):
    # 实例化app
    app = Flask(__name__)

    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    db.init_app(app)
    CORS(app)

    # 项目启动时自动创建数据库
    with app.test_request_context():
        from .models import User, Role, Permission
        db.drop_all()
        db.create_all()
        # 添加角色
        Role.insert_roles()
        # 添加超级管理员
        User.insert_admin()
        # 添加权限
        Permission.insert_permission()

    # 注册main组件的蓝图
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    # 注册api组件的蓝图
    from .api import api as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')

    return app
