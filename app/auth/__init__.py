from flask import Blueprint

# 创建蓝图main
auth = Blueprint('auth', __name__)

from . import auths
