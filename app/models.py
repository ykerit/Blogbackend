from app import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


# 时间日期生成
def gen_time():
    return datetime.now()


def set_info(body):
    info = body[:20]
    s = ''
    for str in info:
        s = s + str.strip('#|*`')
    return s.strip().replace(' ', ',') + '...'


# 权限
class Permission(db.Model):
    __tablename__ = 'permission'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    url = db.Column(db.String(255), index=True)
    method = db.Column(db.String(255), index=True)
    role = db.Column(db.Integer, db.ForeignKey('roles.id'))  # 所属组
    create_time = db.Column(db.DateTime, index=True)

    def __init__(self, name, url, method, role):
        self.name = name
        self.url = url
        self.method = method
        self.role = role
        self.create_time = gen_time()

    @staticmethod
    def insert_permission():

        permissions = [
            {
                'name': '权限查看',
                'url': '/api/permission',
                'method': 'GET',
                'role': 2
            },
            {
                'name': '权限增加',
                'url': '/api/permission',
                'method': 'POST',
                'role': 2
            },
            {
                'name': '插入图片',
                'url': '/api/image',
                'method': 'POST',
                'role': 2
            },
            {
                'name': '查看文章',
                'role': 2,
                'url': '/api/article',
                'method': 'GET'
            }, {
                'name': '查看评论',
                'role': 2,
                'url': '/api/comment',
                'method': 'GET'
            }, {
                'name': '查看后台分类',
                'role': 2,
                'url': '/api/kind',
                'method': 'GET'
            }, {
                'name': '增加标签',
                'role': 2,
                'url': '/api/tag',
                'method': 'POST'
            }, {
                'name': '查看图片',
                'role': 2,
                'url': '/api/image',
                'method': 'GET'
            }, {
                'name': '查看前台分类',
                'role': 2,
                'url': '/api/classification',
                'method': 'GET'
            }, {
                'name': '查看归档',
                'role': 2,
                'url': '/api/filed',
                'method': 'GET'
            }, {
                'name': '撰写评论',
                'role': 2,
                'url': '/api/comment',
                'method': 'POST'
            }, {
                'name': '新建文章',
                'role': 2,
                'url': '/api/article',
                'method': 'POST'
            }, {
                'name': '新建分类',
                'role': 2,
                'url': '/api/kind',
                'method': 'POST'
            }, {
                'name': '查看个人资料',
                'role': 2,
                'url': '/api/user',
                'method': 'GET'
            }, {
                'name': '查看首页分类',
                'role': 2,
                'url': '/api/classification',
                'method': 'GET'
            }, {
                'name': '删除个人文章',
                'role': 2,
                'url': '/api/article',
                'method': 'DELETE'
            }, {
                'name': '查看个人文章',
                'role': 2,
                'url': '/api/user_article',
                'method': 'GET'
            }, {
                'name': '普通用户更改个人资料',
                'role': 2,
                'url': '/api/user',
                'method': 'PUT'
            }
        ]
        for i in permissions:
            result = Permission.query.filter_by(name=i['name']).count()
            if result is 0:
                permission = Permission(name=i['name'], url=i['url'], method=i['method'], role=i['role'])
                db.session.add(permission)
        db.session.commit()


# 类别
class Kind(db.Model):
    __tablename__ = 'kind'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    create_time = db.Column(db.DateTime, index=True)
    article = db.relationship("Article", backref='kind')

    def __init__(self, name):
        self.create_time = gen_time()
        self.name = name

    # json序列
    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


# 文章
class Article(db.Model):
    __tablename__ = 'article'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    info = db.Column(db.Text)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    tag = db.Column(db.String(128))
    create_time = db.Column(db.DateTime, index=True)
    star = db.Column(db.SmallInteger, default=0)
    kind_id = db.Column(db.Integer, db.ForeignKey('kind.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comments = db.relationship("Comment", backref='article')

    def __init__(self, title, body, body_html, kind, tag, user_id):
        self.title = title
        self.body = body
        self.body_html = body_html
        self.info = set_info(body)
        self.kind_id = kind
        self.tag = tag
        self.create_time = gen_time()
        self.user_id = user_id

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
    content = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'))
    create_time = db.Column(db.DateTime, index=True)

    def __init__(self, content, user_id, article_id):
        self.content = content
        self.user_id = user_id
        self.article_id = article_id
        self.create_time = gen_time()

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
    user = db.relationship('User', backref='roles', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = ['管理员', '普通用户']
        for r in roles:
            result = Role.query.filter_by(role_name=r).count()
            if result is 0:
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
    create_time = db.Column(db.DateTime, index=True)
    password_hash = db.Column(db.String(128))
    face = db.Column(db.String(255))  # 头像
    title = db.Column(db.String(50), default='暂无')  # 技术栈
    group = db.Column(db.String(25), default='暂无')  # 学历
    signature = db.Column(db.String(100), default='海纳百川，有容乃大')  # 个人签名
    tag = db.Column(db.String(128), default='贵族')  # 标签
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    article = db.relationship('Article', backref='user', lazy='dynamic')
    user_logs = db.relationship('Userlog', backref='user')  # 会员日志外键关系关联
    comments = db.relationship('Comment', backref='user')  # 评论外键关联

    def __init__(self, name, password, role):
        self.name = name
        self.password_hash = generate_password_hash(password)
        self.role_id = role
        self.create_time = gen_time()
        self.face = 'https://s2.ax1x.com/2019/03/21/A3Z2pn.jpg'

    @staticmethod
    def insert_admin():
        result = User.query.filter_by(name='yker').count()
        if result is 0:
            admin = User(name='yker', password='yker123', role=1)
            db.session.add(admin)
        db.session.commit()

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
    reason = db.Column(db.String(50))
    create_time = db.Column(db.DateTime, index=True)

    def __init__(self, user_id, reason):
        self.create_time = gen_time()
        self.user_id = user_id
        self.reason = reason

    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict


# 操作日志
class Oplog(db.Model):
    __tablename__ = 'oplog'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip = db.Column(db.String(100))
    reason = db.Column(db.String(600))
    create_time = db.Column(db.DateTime, index=True)

    def __init__(self, id, reason):
        self.create_time = gen_time()
        self.reason = reason
        self.user_id = id

    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict
