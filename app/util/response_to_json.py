from flask import jsonify
import re


def gen_tag(tag):
    tag_list = re.split('-', tag)
    if tag_list[0] == '':
        tag_list[0] = '原创'
    return tag_list


# 返回当前登录信息
def current_user(user, token):
    return jsonify(dict(currentUser={
        'isAuthorization': 'true',
        'id': user.id,
        'face': user.face,
        'role': user.role_id,
        'name': user.name,
        'title': user.title,
        'group': user.group,
        'signature': user.signature,
        'tag': gen_tag(user.tag),
        'token': token,
    }, status=200))
