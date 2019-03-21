from flask import jsonify, request, g
import jwt
from datetime import datetime, timedelta
from app.models import User, Userlog, Oplog, Permission
from . import auth
from .. import db
# 管理员 与 普通用户
ADMINISTRATOR = 1
ORDINARY = 2


# jwt以及权限验证
class Auth:
    def __init__(self):
        pass

    # 生成token
    @staticmethod
    def encode_token(user_name):
        try:

            headers = {
                "typ": "JWT",
                "alg": "HS256",
            }
            payload = {
                "headers": headers,
                'exp': datetime.utcnow() + timedelta(days=0, seconds=10),
                'iat': datetime.utcnow(),
                'iss': 'yker',
                'data': {
                    'user_name': user_name
                }
            }
            return jwt.encode(payload, 'secret', 'HS256')
        except Exception as e:
            return e

    # token验证
    @staticmethod
    def decode_token(token):
        try:
            payload = jwt.decode(token, 'secret', options={'verify_exp': False})
            if 'data' in payload and 'user_name' in payload['data']:
                return payload
            else:
                raise jwt.InvalidTokenError

        except jwt.ExpiredSignatureError:
            return "Token过期"
        except jwt.InvalidTokenError:
            return "无效的Token"

    # 匿名用户api权限
    @staticmethod
    def anonymous_authentication(path, methods):
        # 匿名访问控制
        anonymous_authentication = [{
            'url': '/api/article',
            'method': 'GET'
        }, {
            'url': '/api/comment',
            'method': 'GET'
        }, {
            'url': '/api/kind',
            'method': 'GET'
        }, {
            'url': '/api/tag',
            'method': 'GET'
        }, {
            'url': '/api/image',
            'method': 'GET'
        }, {
            'url': '/api/classification',
            'method': 'GET'
        }, {
            'url': '/api/filed',
            'method': 'GET'
        }]
        # 去掉多余url参数
        if path.count('/') > 2:
            path = path[0:path.rfind('/')]
        # 返回结果
        for item in anonymous_authentication:
            if path == item['url'] and methods == item['method']:
                return True
            else:
                continue
        return False

    # 管理员&&普通会员api权限验证
    @staticmethod
    def route_interception(path, methods, role):
        # 去掉多余url参数
        if path.count('/') > 2:
            path = path[0:path.rfind('/')]

        permission = Permission.query.\
            filter_by(url=path, method=methods, role=role).first()
        if permission is not None:
            return True
        else:
            return False

    @staticmethod
    def identify():
        params = request.headers.get('Authorization')
        path = request.path
        methods = request.method

        if params is not None and params != 'null':

            # 是否为字符串
            auth_token = Auth.decode_token(params)
            if isinstance(auth_token, str):
                return {
                    'flag': 'error',
                    'msg': auth_token,
                    'status': 400
                }
            if not auth_token or auth_token['headers']['typ'] != 'JWT':
                result = {
                    'flag': 'error',
                    'msg': '请传递正确的验证头信息',
                    'status': 400
                }
            else:
                user = User.query.filter_by(name=auth_token['data']['user_name']).first()
                if user is None:
                    result = {
                        'flag': 'error',
                        'msg': '找不到该用户信息',
                        'status': 400
                    }
                else:
                    g.user_id = user.id
                    if user.role_id == ADMINISTRATOR:
                        result = {
                            'flag': 'success',
                            'msg': '请求成功',
                            'status': 200
                        }
                    elif Auth.route_interception(path, methods, user.role_id):
                        result = {
                            'flag': 'success',
                            'msg': '请求成功',
                            'status': 200
                        }
                    else:
                        result = {
                            'flag': 'error',
                            'msg': '无权限',
                            'status': 400
                        }
        else:
            if Auth.anonymous_authentication(path, methods):
                result = {
                        'flag': 'success',
                        'msg': '匿名请求成功',
                        'status': 200
                }
            else:
                result = {
                    'flag': 'error',
                    'msg': '没有提供认证token',
                    'status': 400
                }
        return result


@auth.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(name=request.form.get('name')).first()
    password = request.form.get('password')

    if user is not None and user.verify_password(password=password):
        user_log = Userlog(user_id=user.id)
        db.session.add(user_log)
        db.session.commit()

        return jsonify({'is_authorization': 'true',
                        'id': user.id,
                        'name': request.form.get('name'),
                        'token': str(Auth.encode_token(user.name), encoding='utf-8'),
                        'image_url': user.face,
                        'status': 200})
    return jsonify({'is_authorization': 'false', 'status': 400})


# 注册
@auth.route('/register', methods=['POST'])
def register():
    name = request.form.get('name')
    password = request.form.get('password')
    if name and password:
        record = User.query.filter_by(name=name).count()
        if record == 0:
            user = User(name=name, password=password, role=ORDINARY)
            db.session.add(user)
            op_log = Oplog(reason='用户注册')
            db.session.add(op_log)
            db.session.commit()
            users = User.query.filter_by(name=request.form.get('name')).first()
            return jsonify({
                'id': users.id,
                'is_authorization': 'true',
                'name': users.name,
                'token': str(Auth.encode_token(users.name), encoding='utf-8'),
                'status': 200
            })
        return jsonify({'flag': 'error',
                        'reason': '该账号已经注册',
                        'status': 400})
    return jsonify({'flag': 'error',
                    'status': 400})
