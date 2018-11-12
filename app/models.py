from app import db,login_manage
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


# 权限
class Permission:
    FOLLOW = 0x01  # 喜欢
    COMMENT = 0x02  # 全开发评论权限
    WRITE_ARTICLES = 0x04  # 文章权限
    MODERATE_COMMENTS = 0x08  # 半开放评论权限
    ADMINISTER = 0x80  # 管理员

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

    def __init__(self, title, body, body_html, kind, link):
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

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

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
    # 一对多

    def __init__(self, name, password):
        self.name = name
        self.password = password
        self.create_time = datetime.utcnow()
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