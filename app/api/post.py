from flask import jsonify, request
from app.models import User, Article, Role
from . import api
from .. import db
from manage import app


# 登录验证
@api.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(name=request.form.get('userName')).first()
    password = request.form.get('password')

    if user is not None and user.verify_password(password=password):
        return jsonify({'is_authorization': 'true', 'name': request.form.get('userName'), 'token': user.password_hash})
    else:
        return jsonify({'is_authorization': 'false'})


# 用户api 增删改查
@api.route('/user', methods=['GET'])
def get_all_user():
    users = User.query.all()
    return jsonify({'user': [user.to_json() for user in users], 'status': 100})


@api.route('/user', methods=['POST'])
def add_user():
    if not request.json or not 'name' in request.json or not 'password' in request.json or not 'role_id' in request.json:
        return jsonify({'status': 400})

    name = request.json['name']
    password = request.json['password']
    role_id = request.json['role_id']
    if int(role_id) == 1:
        role = db.session.query(Role).filter(Role.id == '1').one()
        old_number = role.number
        role.number = old_number + 1
    else:
        role = db.session.query(Role).filter(Role.id == '2').one()
        role.number = int(role.number) + 1
    user = User(name=name, password=password, role_id=role_id)
    db.session.add(user)
    db.session.commit()

    return jsonify({'flag': 'success',
                    'status': 200, })


@api.route('/user', methods=['PUT'])
def update_user():
    pass


@api.route('/user', methods=['DELETE'])
def delete_user():
    pass


# 文章api
# 获得所有文章
@api.route('/article', methods=['GET'])
def get_all_article():
    articles = Article.query.all()
    return jsonify({'article': [article.to_json() for article in articles], 'status': 100})


# 根据文章id获取文章
@api.route('/article/<id>', methods=['GET'])
def get_article(id):
    pass


# 添加文章
@api.route('/article', methods=['POST'])
def add_article():
    if not request.json or not 'title' in request.json or not 'body' in request.json \
            or not 'body_html' in request.json or not 'kind' in request.json \
            or not 'link' in request.json:
        return jsonify({'status': 400})

    article = Article(title=request.json['title'], body=request.json['body'],
                      body_html=request.json['body_html'],
                      kind=request.json['kind'], link=request.json['link'])
    db.session.add(article)
    db.session.commit()
    return jsonify({'flag': 'success',
                    'status': 200, })


# 更新文章
@api.route('/article/<id>', methods=['put'])
def update_article(id):
    pass


@api.route('/article/<id>', methods=['DELETE'])
def delete_article(id):
    pass


@api.route('/role', methods=['GET'])
def get_role():
    roles = Role.query.all()
    return jsonify({'user': [role.to_json() for role in roles], 'status': 100})