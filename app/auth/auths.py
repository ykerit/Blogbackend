from flask import jsonify, request
import jwt
from datetime import datetime, timedelta
from app.models import User, Userlog, Oplog
from . import auth
from .. import db

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

    @staticmethod
    def identify():

        params = request.headers.get('Authorization')

        if params:
            auth_token = Auth.decode_token(request.headers.get('Authorization'))
            if isinstance(auth_token, str):
                return {
                    'flag': 'error',
                    'msg': auth_token
                }
            if not auth_token or auth_token['headers']['typ'] != 'JWT':
                result = {
                    'flag': 'error',
                    'msg': '找不到该用户信息'}
            else:
                user = User.query.filter_by(name=auth_token['data']['user_name']).first()
                if user is None:
                    result = {
                        'flag': 'error',
                        'msg': '请传递正确的验证头信息'}
                else:
                    result = {
                        'flag': 'success',
                        'msg': '请求成功'}
        else:
            result = {
                    'flag': 'error',
                    'msg': '没有提供认证token'}
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
                        'status': 200})
    return jsonify({'is_authorization': 'false', 'status': 400})


# 注册
@auth.route('/auth/register', methods=['POST'])
def register():
    name = request.form.get('name')
    password = request.form.get('password')
    if name and password:
        record = User.query.filter_by(name=name).count()
        if record is 0:
            user = User(name=name, password=password, role=ORDINARY)
            db.session.add(user)
            db.session.commit()
            op_log = Oplog(reason='用户注册')
            db.session.add(op_log)
            db.session.commit()
            users = User.query.filter_by(name=request.form.get('name')).first()
            return jsonify({'is_authorization': 'true',
                            'name': users.name,
                            'token': Auth.encode_token(users.name),
                            'status': 200})
        return jsonify({'flag': 'error',
                        'reason': '该账号已经注册',
                        'status': 400})
    return jsonify({'flag': 'error',
                    'status': 400})