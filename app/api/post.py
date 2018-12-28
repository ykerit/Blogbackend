from flask import jsonify, request
# from sqlalchemy import func
from app.models import User, Article, Role, Admin, Adminlog, Oplog, Userlog, Comment
from . import api
from .. import db
from manage import app


# 生成log json
def gen_json(object):
    result = []
    for obj in object:
        result.append({'id': obj.id, 'name': obj.name,
                       'create_time': obj.create_time,
                       'ip': obj.ip})
    return result


# 登录验证
@api.route('/api/login', methods=['POST'])
def login():
    user = User.query.filter_by(name=request.form.get('name')).first()
    admin = Admin.query.filter_by(name=request.form.get('name')).first()
    password = request.form.get('password')

    if user is not None and user.verify_password(password=password):
        user_log = Userlog(user_id=user.id)
        db.session.add(user_log)
        db.session.commit()
        return jsonify({'is_authorization': 'true', 'name': request.form.get('name'), \
                        'token': user.uuid, 'status': 200})

    if admin is not None and admin.verify_password(password=password):
        admin_log = Adminlog(admin_id=admin.id)
        db.session.add(admin_log)
        db.session.commit()
        return jsonify({'is_authorization': 'true', 'name': request.form.get('name'), \
                        'token': admin.uuid, 'status': 200})
    else:
        return jsonify({'is_authorization': 'false'})


# 用户api 增删改查
@api.route('/api/user', methods=['GET'])
def get_user():
    page_size = request.args.get('page_size')
    users = User.query.outerjoin(Role).add_columns(User.id,
                                                   User.name,
                                                   User.uuid,
                                                   User.create_time,
                                                   Role.role_name).\
        paginate(int(page_size), per_page=10, error_out=False)
    result = []
    for user in users.items:
        result.append({'id': user.id, 'name': user.name, 'role': user.role_name,
                       'create_time': user.create_time, 'uuid': user.uuid})
    return jsonify({'userData': result, 'user_total': users.total, 'status': 200})


@api.route('/api/user', methods=['POST'])
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


@api.route('/api/user', methods=['PUT'])
def update_user():
    pass


@api.route('/api/user/<int:id>', methods=['DELETE'])
def delete_user(id):
    if id is None and User.query.filter_by(id=id).first() is None:
        return jsonify({'status': 400})

    user = User.query.filter_by(id=id).first()
    db.session.delete(user)
    op_log = Oplog(reason='删除用户')
    db.session.add(op_log)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 文章api
# 获得所有文章
@api.route('/api/article', methods=['GET'])
def get_all_article():
    page_size = request.args.get('page_size')
    articles = Article.query.add_columns(Article.id,
                                         Article.title,
                                         Article.create_time,
                                         Article.info,
                                         Article.star,
                                         Article.comment_number).\
        paginate(int(page_size), per_page=4, error_out=False)

    result = []
    app.logger.info(articles.total)
    for article in articles.items:
        result.append({'id': article.id, 'title': article.title,
                       'create_time': article.create_time,
                       'description': article.info, 'star': article.star,
                       'comment': article.comment_number})
    
    return jsonify({'articleList': result,
                    'total': articles.total, 'status': 200})


# 根据文章id获取文章
@api.route('/api/article/<int:id>', methods=['GET'])
def get_article(id):
    if id is None and Article.query.filter_by(id=id).first() is None:
        return jsonify({'status': 400})
    articles = Article.query.filter_by(id=id).add_columns(Article.id, Article.title, Article.create_time,
                                                          Article.body_html)
    result = []
    for article in articles:
        result.append({'id': article.id, 'title': article.title,
                       'create_time': article.create_time, 'html': article.body_html})
    return jsonify({'articleContent': result, 'status': 200})


# 添加文章
@api.route('/api/article', methods=['POST'])
def add_article():
    if not request.json or not 'title' in request.json or not 'body' in request.json \
            or not 'body_html' in request.json:
        return jsonify({'status': 400})

    article = Article(title=request.json['title'], body=request.json['body'],
                      body_html=request.json['body_html'])
    op_log = Oplog(reason='发布文章')
    db.session.add(article)
    db.session.add(op_log)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 更新文章
@api.route('/api/article/<int:id>', methods=['put'])
def update_article():
    pass


@api.route('/api/article/<int:id>', methods=['DELETE'])
def delete_article(id):
    if id is None and Article.query.filter_by(id=id).first() is None:
        return jsonify({'status': 400})
    articel = Article.query.filter_by(id=id).first()
    op_log = Oplog(reason='删除文章')
    db.session.delete(articel)
    db.session.add(op_log)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 角色设置
@api.route('/api/role', methods=['GET'])
def get_role():
    roles = Role.query.all()
    return jsonify({'roleData': [role.to_json() for role in roles], 'status': 200})


@api.route('/api/role', methods=['POST'])
def add_role():
    name = request.json['name']

    if name is not None:
        role = Role(role_name=name)
        db.session.add(role)
        db.session.commit()

        return jsonify({'flag': 'success', 'status': 200})
    else:
        return jsonify({'status': 400})


@api.route('/api/role/<int:id>', methods=['DELETE'])
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
@api.route('/api/admin', methods=['GET'])
def get_admin():
    page_size = request.args.get('page_size')
    admins = Admin.query.outerjoin(Role).add_columns(Admin.id,
                                                     Admin.name,
                                                     Admin.uuid,
                                                     Admin.create_time,
                                                     Role.role_name).\
        paginate(int(page_size), per_page=10, error_out=False)
    result = []
    for admin in admins.items:
        result.append({'id': admin.id, 'name': admin.name,
                       'role': admin.role_name, 'create_time': admin.create_time,
                       'uuid': admin.uuid})

    return jsonify({'adminData': result, 'admin_total': admins.total, 'status': 200})


@api.route('/api/admin', methods=['POST'])
def add_admin():
    if not request.json or not 'name' in request.json or not 'password' in request.json:
        return jsonify({'status': 400})

    name = request.json['name']
    password = request.json['password']

    admin = Admin(name=name, password=password)
    db.session.add(admin)
    db.session.commit()
    op_log = Oplog(reason='添加用户')
    db.session.add(op_log)
    db.session.commit()

    return jsonify({'flag': 'success',
                    'status': 200, })


@api.route('/api/admin/<int:id>', methods=['DELETE'])
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
@api.route('/api/comment/<int:id>', methods=['GET'])
def get_comment(id):
    page_size = request.args.get('page_size')
    if id is None and Comment.query.filter_by(id=id).first() is None:
        return jsonify({'status': 400})
    comments = Comment.query.filter_by(id=id).paginate(int(page_size), per_page=10, error_out=False)
    return jsonify({'comment': [comment.to_json() for comment in comments], 'status': 200})


@api.route('/api/comment', methods=['POST'])
def add_comment():
    if request.json['id'] and request.json['user_id'] is None:
        return jsonify({'status': 400})
    comment = Comment(content=request.json['content'], user_id=request.json['user_id'])
    db.session.add(comment)
    db.session.commit()
    return jsonify({'flag': 'success', 'status': 200})


# 权限管理


# 日志
@api.route('/api/admin_log', methods=['GET'])
def get_admin_log():
    page_size = request.args.get('page_size')
    logs = Adminlog.query.outerjoin(Admin).add_columns(Adminlog.id,
                                                       Admin.name,
                                                       Adminlog.ip,
                                                       Adminlog.create_time).\
        paginate(int(page_size), per_page=10, error_out=False)

    return jsonify({'AdminLog': gen_json(logs.items), 'adminLog_total': logs.total, 'status': 200})


@api.route('/api/user_log', methods=['GET'])
def get_user_log():
    page_size = request.args.get('page_size')
    logs = Userlog.query.outerjoin(User).add_columns(Userlog.id,
                                                     User.name,
                                                     Userlog.ip,
                                                     Userlog.create_time).\
        paginate(int(page_size), per_page=10, error_out=False)

    return jsonify({'UserLog': gen_json(logs.items), 'userLog_total': logs.total, 'status': 200})


@api.route('/api/op_log', methods=['GET'])
def get_op_log():
    page_size = request.args.get('page_size')
    logs = Oplog.query.outerjoin(Admin).add_columns(Oplog.id,
                                                    Admin.name,
                                                    Oplog.ip,
                                                    Oplog.create_time,
                                                    Oplog.reason).\
        paginate(int(page_size), per_page=10, error_out=False)
    result = []
    for obj in logs.items:
        result.append({'id': obj.id, 'name': obj.name,
                       'create_time': obj.create_time,
                       'ip': obj.ip, 'reason': obj.reason})
    return jsonify({'OpLog': result, 'op_total': logs.total, 'status': 200})
