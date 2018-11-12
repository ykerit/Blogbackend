from app import db,login_manage
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


'''
表1 Article
|id|title|body|body_html|kind|create_time|link|
|  |     |    |         |    |          |    |
'''


class Article(db.Model):
    __tablename__ = 'article'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    kind = db.Column(db.String(20))
    create_time = db.Column(db.DateTime, index=True)
    link = db.Column(db.String(128))

    def __init__(self,title, body, body_html, kind, link):
        self.title = title
        self.body = body
        self.body_html = body_html
        self.kind = kind
        self.create_time = datetime.utcnow()
        self.link = link

    def __repr__(self):
        return '' % (self.id, self.title)

    # json序列
    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


'''
表2 role表 
|role_id|role   |
|    1  |管理员  |
|    2  |普通用户 |
'''


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    number = db.Column(db.Integer)
    # 一对多
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '' % (self.id, self.name)

    # json序列化
    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


'''
表3  user表
|user_id |name|passwd|creat_time|
|        |    |      |        |
'''


class User(db.Model,UserMixin):
    # 表名
    __tablename__ = 'user'
    # 字段
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(16), unique=True)
    password = db.Column(db.String(20))
    create_time = db.Column(db.DateTime, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))

    def __init__(self, name, password, role_id):
        self.name = name
        self.password = password
        self.create_time = datetime.utcnow()
        self.role_id = role_id
        self.password_hash = generate_password_hash(password)

    def __repr__(self):
        return '' % (self.id, self.name)

    # json序列化
    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict

    def verify_password(self, password):
        if self.password_hash is None:
            return False
        else:
            return check_password_hash(self.password_hash, password)


@login_manage.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))