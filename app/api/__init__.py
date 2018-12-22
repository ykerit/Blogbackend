from flask import Blueprint

# 创建蓝图api
api = Blueprint('api', __name__)

from . import post,error