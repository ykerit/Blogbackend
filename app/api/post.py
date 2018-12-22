from flask import jsonify, request
from app.models import User, Article, Role, Admin, Adminlog, Oplog, Userlog, Comment
from . import api
from .. import db
from manage import app


# 登录验证
@api.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(name=request.form.get('name')).first()
    admin = Admin.query.filter_by(name=request.form.get('name')).first()
    password = request.form.get('password')

    if user is not None and user.verify_password(password=password):
        user_log = Userlog(user_id=user.id)
        db.session.add(user_log)
        db.session.commit()
        return jsonify({'is_authorization': 'true', 'name': request.form.get('name'),\
                        'token': user.uuid, 'status': 200})

    if admin is not None and admin.verify_password(password=password):
        admin_log = Adminlog(admin_id=admin.id)
        db.session.add(admin_log)
        db.session.commit()
        return jsonify({'is_authorization': 'true', 'name': request.form.get('name'),\
                        'token': admin.uuid, 'status': 200})

    else:
        return jsonify({'is_authorization': 'false'})


# 用户api 增删改查
@api.route('/user', methods=['GET'])
def get_user():
    users = User.query.outerjoin(Role).add_columns(User.id, User.name, User.uuid,
                                                   User.create_time, Role.role_name)
    result = []
    for user in users:
        result.append({'id': user.id, 'name': user.name, 'role': user.role_name,
                       'create_time': user.create_time, 'uuid': user.uuid})
    return jsonify({'user': result, 'status': 200})


@api.route('/user', methods=['POST'])
def add_user():
    if not request.json or not 'name' in request.json or not 'password' in request.json:
        return jsonify({'status': 400})

    name = request.json['name']
    password = request.json['password']

    user = User(name=name, password=password)
    db.session.add(user)
    db.session.commit()
    op_log = Oplog(reason='添加用户')
    db.session.add(op_log)
    db.session.commit()

    return jsonify({'flag': 'success',
                    'status': 200, })


@api.route('/user', methods=['PUT'])
def update_user():
    pass


@api.route('/user/<int:id>', methods=['DELETE'])
def delete_user(id):

    if id is None and User.query.filter_by(id=id).first() is None:
        return jsonify({'status': 400})

    user = User.query.filter_by(id=id).first()
    db.session.delete(user)
    op_log = Oplog(reason='删除文章')
    db.session.add(op_log)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 文章api
# 获得所有文章
@api.route('/article', methods=['GET'])
def get_all_article():
    articles = Article.query.limit(10).all()
    return jsonify({'article': [article.to_json() for article in articles], 'status': 200})


# 根据文章id获取文章
@api.route('/article/<ids>', methods=['GET'])
def get_article(ids):
    article = Article.query.filter_by(id=ids)
    if article is not None:
        return jsonify({'item': [item.to_json() for item in article]})
    else:
        return jsonify({'status': 400})


# 添加文章
@api.route('/article', methods=['POST'])
def add_article():
    if not request.json or not 'title' in request.json or not 'body' in request.json \
            or not 'body_html' in request.json or not 'link' in request.json:
        return jsonify({'status': 400})

    article = Article(title=request.json['title'], info=request.json['info'],
                      body_html=request.json['body_html'], url=request.json['url'])
    db.session.add(article)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 更新文章
@api.route('/article/<id>', methods=['put'])
def update_article():
    pass


@api.route('/article/<id>', methods=['DELETE'])
def delete_article(id):
    if id is None and Article.query.filter_by(id=id).first() is None:
        return jsonify({'status': 200})
    articel = Article.query.filter_by(id=id).first()
    op_log = Oplog(reason='删除文章')
    db.session.delete(articel)
    db.session.add(op_log)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 角色设置
@api.route('/role', methods=['GET'])
def get_role():
    roles = Role.query.all()
    return jsonify({'role': [role.to_json() for role in roles], 'status': 200})


@api.route('/role', methods=['POST'])
def add_role():
    name = request.json['name']

    if name is not None:
        role = Role(role_name=name)
        db.session.add(role)
        db.session.commit()

        return jsonify({'flag': 'success', 'status': 200})
    else:
        return jsonify({'status': 400})


@api.route('/role/<int:id>', methods=['DELETE'])
def delete_role(id):

    if id is None and Role.query.filter_by(id=id).first() is None:
        return jsonify({'status': 400})

    role = Role.query.filter_by(id=id).first()
    db.session.delete(role)
    op_log = Oplog(reason='删除角色')
    db.session.add(op_log)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 管理员
@api.route('/admin', methods=['GET'])
def get_admin():
    admins = User.query.outerjoin(Role).add_columns(Admin.id, Admin.name, Admin.uuid,
                                                    Admin.create_time, Role.role_name)
    result = []
    for admin in admins:
        result.append({'id': admin.id, 'name': admin.name, 'role': admin.role_name, 'create_time': admin.create_time,
                       'uuid': admin.uuid})

    return jsonify({'admin': result, 'status': 200})


@api.route('/admin', methods=['POST'])
def add_admin():
    name = request.json['name']
    password = request.json['password']

    if name and password is not None:
        admin = Admin(name=name, password=password)
        db.session.add(admin)
        db.session.commit()
        return jsonify({'flag': 'success', 'status': 200})
    else:
        return jsonify({'status': 400})


@api.route('/admin/<int:id>', methods=['DELETE'])
def delete_admin(id):

    if id is None and Admin.query.filter_by(id=id).first() is None:
        return jsonify({'status': 400})

    admin = Admin.query.filter_by(id=id).first()
    db.session.delete(admin)
    op_log = Oplog(reason='删除管理员')
    db.session.add(op_log)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 评论
@api.route('/comment/<int:id>', methods=['GET'])
def get_comment(id):
    if id is None and Comment.query.filter_by(id=id).first() is None:
        return jsonify({'status': 400})
    comments = Comment.query.filter_by(id=id).all()
    return jsonify({'comment': [comment.to_json() for comment in comments], 'status': 200})


@api.route('/comment', methods=['POST'])
def add_comment():
    if request.json['id'] and request.json['user_id'] is None:
        return jsonify({'status': 400})
    comment = Comment(content=request.json['content'], user_id=request.json['user_id'])
    db.session.add(comment)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})

# 权限管理
