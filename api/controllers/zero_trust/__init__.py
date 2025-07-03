"""零信任系统控制器包"""

from flask import Blueprint
from flask_restful import Api

# 创建零信任系统的蓝图
zero_trust_bp = Blueprint('zero_trust', __name__, url_prefix='/api/zero-trust')
zero_trust_api = Api(zero_trust_bp)

# 导入并注册路由
from . import auth