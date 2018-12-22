from app import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import uuid


def gen_uuid():
    return uuid.uuid1().hex


# 权限
class Permission(db.Model):
    __tablename__ = 'permission'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    url = db.Column(db.String(255), unique=True)
    role = db.Column(db.Integer, db.ForeignKey('roles.id'))  # 所属组
    create_time = db.Column(db.DateTime, index=True, default=datetime.now())


# 标签
class Tag(db.Model):
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    create_time = db.Column(db.DateTime, index=True, default=datetime.now())
    article = db.relationship("Article", backref='tag')


# 文章
class Article(db.Model):
    __tablename__ = 'article'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    info = db.Column(db.Text)
    body_html = db.Column(db.Text)
    create_time = db.Column(db.DateTime, index=True)
    url = db.Column(db.String(128))
    star = db.Column(db.SmallInteger)
    comment_number = db.Column(db.BigInteger)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comments = db.relationship("Comment", backref='article')

    def __init__(self, title, info, body_html, kind, url):
        self.title = title
        self.info = info
        self.body_html = body_html
        self.kind = kind
        self.create_time = datetime.now()
        self.url = url

    def __repr__(self):
        return "<Article %r>" % self.title

    # json序列
    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


# 评论
class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Integer, db.ForeignKey('article.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    create_time = db.Column(db.DateTime, index=True, default=datetime.now())

    def __repr__(self):
        return '<Comment %r>' % self.id

    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


# 角色
class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String, unique=True)
    permission = db.relationship("Permission", backref='roles')
    admin = db.relationship('Admin', backref='roles', lazy='dynamic')
    user = db.relationship('User', backref='roles', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = ['管理员', '普通用户']
        for r in roles:
            role = Role.query.filter_by(role_name=r).first()
            if role is None:
                role = Role(role_name=r)
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


# 用户
class User(db.Model, UserMixin):
    # 表名
    __tablename__ = 'user'
    # 字段
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(16), unique=True)
    create_time = db.Column(db.DateTime, index=True, default=datetime.now())
    password_hash = db.Column(db.String(128))
    face = db.Column(db.String(255), unique=True)
    uuid = db.Column(db.String(255), unique=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), default=2)
    article = db.relationship('Article', backref='user', lazy='dynamic')
    user_logs = db.relationship('Userlog', backref='user')  # 会员日志外检关系关联
    comments = db.relationship('Comment', backref='user')  # 评论外键关联

    def __init__(self, name, password):
        self.name = name
        self.password_hash = generate_password_hash(password)
        self.uuid = gen_uuid()

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


# 会员登录日志
class Userlog(db.Model):
    __tablename__ = 'userlog'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip = db.Column(db.String(100))
    create_time = db.Column(db.DateTime, index=True, default=datetime.now())

    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


# 管理员
class Admin(db.Model):
    __tablename = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), default=1)
    uuid = db.Column(db.String(255), unique=True)
    create_time = db.Column(db.DateTime, index=True, default=datetime.now())
    admin_logs = db.relationship('Adminlog', backref='admin')
    op_logs = db.relationship('Oplog', backref='admin')

    def __init__(self, name, password):
        self.name = name
        self.password_hash = generate_password_hash(password)
        self.uuid = gen_uuid()

    def __repr__(self):
        return "<Admin %r>" % self.id

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


# 管理员日志
class Adminlog(db.Model):
    __tablename__ = 'adminlog'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))
    create_time = db.Column(db.DateTime, index=True, default=datetime.now())

    def __repr__(self):
        return "<Admin %r>" % self.id

    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


# 操作日志
class Oplog(db.Model):
    __tablename__ = 'oplog'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))
    reason = db.Column(db.String(600))
    create_time = db.Column(db.DateTime, index=True, default=datetime.now())

    def __repr__(self):
        return "<opmin %r>" % self.id

    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


