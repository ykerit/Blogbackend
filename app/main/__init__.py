from flask import Blueprint
#创建蓝图main
main = Blueprint('main', __name__)

from . import views