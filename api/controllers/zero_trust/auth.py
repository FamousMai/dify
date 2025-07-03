"""零信任认证API控制器

提供零信任系统的认证相关API端点：
- 用户登录
- Token验证  
- 获取用户信息
- 用户登出
"""

import logging
from typing import Optional

from flask import current_app, request
from flask_restful import Resource, reqparse
from werkzeug.exceptions import BadRequest, Unauthorized

from services.zero_trust_auth_service import ZeroTrustAuthService
from services.zero_trust_user_service import ZeroTrustUserService

from . import zero_trust_api

logger = logging.getLogger(__name__)


def get_bearer_token() -> Optional[str]:
    """从Authorization头获取Bearer Token"""
    authorization = request.headers.get('Authorization')
    if not authorization:
        return None
    
    parts = authorization.split(' ')
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    
    return parts[1]


def require_zero_trust_auth():
    """零信任认证装饰器"""
    token = get_bearer_token()
    if not token:
        raise Unauthorized("缺少认证Token")
    
    user = ZeroTrustAuthService.verify_token(token)
    if not user:
        raise Unauthorized("Token无效或已过期")
    
    return user, token


class ZeroTrustLoginResource(Resource):
    """零信任用户登录"""
    
    def post(self):
        """用户登录
        
        Body:
        {
            "username": "用户名或邮箱",
            "password": "密码"
        }
        
        Returns:
        {
            "success": true,
            "token": "jwt_token",
            "redirect_url": "跳转地址",
            "user": {...}
        }
        """
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='用户名不能为空')
        parser.add_argument('password', type=str, required=True, help='密码不能为空')
        args = parser.parse_args()
        
        try:
            username = args['username'].strip()
            password = args['password']
            
            if not username or not password:
                raise BadRequest("用户名和密码不能为空")
            
            # 认证用户
            user = ZeroTrustAuthService.authenticate_user(username, password)
            if not user:
                raise Unauthorized("用户名或密码错误")
            
            # 生成Token
            token = ZeroTrustAuthService.generate_token(user)
            
            # 构造返回数据
            redirect_url = request.args.get('redirect_url', current_app.config.get('DIFY_WEB_URL', '/'))
            
            response_data = {
                "success": True,
                "token": token,
                "redirect_url": redirect_url,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "name": user.name,
                    "department": user.department,
                    "role": user.role
                }
            }
            
            logger.info(f"用户登录成功: {user.username}")
            return response_data
            
        except Exception as e:
            logger.error(f"用户登录失败: {str(e)}")
            if isinstance(e, (BadRequest, Unauthorized)):
                raise
            raise BadRequest("登录失败，请重试")


class ZeroTrustTokenInfoResource(Resource):
    """获取Token用户信息（模拟外部API）"""
    
    def get(self):
        """获取Token关联的用户信息
        
        Headers:
        Authorization: Bearer <token>
        
        Returns:
        {
            "success": true,
            "user": {...}
        }
        """
        try:
            token = get_bearer_token()
            if not token:
                raise Unauthorized("缺少Authorization头")
            
            # 获取用户信息
            user_info = ZeroTrustAuthService.get_user_token_info(token)
            if not user_info:
                raise Unauthorized("Token无效或已过期")
            
            return {
                "success": True,
                "user": user_info
            }
            
        except Exception as e:
            logger.error(f"获取用户Token信息失败: {str(e)}")
            if isinstance(e, Unauthorized):
                raise
            raise BadRequest("获取用户信息失败")


class ZeroTrustTokenVerifyResource(Resource):
    """Token验证"""
    
    def post(self):
        """验证Token
        
        Body:
        {
            "token": "jwt_token"
        }
        
        Returns:
        {
            "valid": true,
            "user_id": "uuid",
            "user": {...}
        }
        """
        parser = reqparse.RequestParser()
        parser.add_argument('token', type=str, required=True, help='Token不能为空')
        args = parser.parse_args()
        
        try:
            token = args['token']
            
            # 验证Token
            user = ZeroTrustAuthService.verify_token(token)
            
            if user:
                return {
                    "valid": True,
                    "user_id": user.id,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "name": user.name,
                        "department": user.department,
                        "role": user.role,
                        "status": user.status
                    }
                }
            else:
                return {
                    "valid": False,
                    "user_id": None,
                    "user": None
                }
                
        except Exception as e:
            logger.error(f"Token验证失败: {str(e)}")
            return {
                "valid": False,
                "user_id": None,
                "user": None,
                "error": str(e)
            }


class ZeroTrustLogoutResource(Resource):
    """用户登出"""
    
    def post(self):
        """用户登出，撤销当前Token
        
        Headers:
        Authorization: Bearer <token>
        
        Returns:
        {
            "success": true,
            "message": "登出成功"
        }
        """
        try:
            user, token = require_zero_trust_auth()
            
            # 撤销Token
            success = ZeroTrustAuthService.revoke_token(token, user.id)
            
            if success:
                return {
                    "success": True,
                    "message": "登出成功"
                }
            else:
                return {
                    "success": False,
                    "message": "登出失败"
                }
                
        except Exception as e:
            logger.error(f"用户登出失败: {str(e)}")
            if isinstance(e, Unauthorized):
                raise
            raise BadRequest("登出失败")


class ZeroTrustUserProfileResource(Resource):
    """用户个人信息"""
    
    def get(self):
        """获取当前用户信息
        
        Headers:
        Authorization: Bearer <token>
        
        Returns:
        {
            "success": true,
            "user": {...}
        }
        """
        try:
            user, _ = require_zero_trust_auth()
            
            return {
                "success": True,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "name": user.name,
                    "department": user.department,
                    "role": user.role,
                    "status": user.status,
                    "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
                    "created_at": user.created_at.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"获取用户信息失败: {str(e)}")
            if isinstance(e, Unauthorized):
                raise
            raise BadRequest("获取用户信息失败")


class ZeroTrustUserListResource(Resource):
    """用户列表（管理员功能）"""
    
    def get(self):
        """获取用户列表
        
        Query Params:
        - page: 页码 (默认1)
        - per_page: 每页数量 (默认20)
        - status: 筛选状态
        - role: 筛选角色
        - search: 搜索关键词
        
        Headers:
        Authorization: Bearer <token>
        
        Returns:
        {
            "success": true,
            "users": [...],
            "pagination": {...}
        }
        """
        try:
            user, _ = require_zero_trust_auth()
            
            # 检查权限（只有管理员可以查看用户列表）
            if user.role != 'admin':
                raise Unauthorized("权限不足")
            
            # 解析查询参数
            page = request.args.get('page', 1, type=int)
            per_page = min(request.args.get('per_page', 20, type=int), 100)  # 限制最大每页数量
            status = request.args.get('status')
            role = request.args.get('role')
            search = request.args.get('search')
            
            # 获取用户列表
            result = ZeroTrustUserService.get_user_list(
                page=page,
                per_page=per_page,
                status=status,
                role=role,
                search=search
            )
            
            return {
                "success": True,
                **result
            }
            
        except Exception as e:
            logger.error(f"获取用户列表失败: {str(e)}")
            if isinstance(e, Unauthorized):
                raise
            raise BadRequest("获取用户列表失败")


class ZeroTrustInitDemoResource(Resource):
    """初始化演示数据"""
    
    def post(self):
        """创建演示用户
        
        Returns:
        {
            "success": true,
            "message": "演示数据创建成功",
            "users": [...]
        }
        """
        try:
            # 创建演示用户
            demo_users = ZeroTrustUserService.create_demo_users()
            
            users_info = []
            for user in demo_users:
                users_info.append({
                    "username": user.username,
                    "email": user.email,
                    "name": user.name,
                    "role": user.role
                })
            
            return {
                "success": True,
                "message": f"成功创建{len(demo_users)}个演示用户",
                "users": users_info
            }
            
        except Exception as e:
            logger.error(f"创建演示数据失败: {str(e)}")
            raise BadRequest("创建演示数据失败")


# 注册API路由
zero_trust_api.add_resource(ZeroTrustLoginResource, '/auth/login')
zero_trust_api.add_resource(ZeroTrustTokenInfoResource, '/auth/getUserTokenInfo')
zero_trust_api.add_resource(ZeroTrustTokenVerifyResource, '/auth/verify')
zero_trust_api.add_resource(ZeroTrustLogoutResource, '/auth/logout')
zero_trust_api.add_resource(ZeroTrustUserProfileResource, '/user/profile')
zero_trust_api.add_resource(ZeroTrustUserListResource, '/user/list')
zero_trust_api.add_resource(ZeroTrustInitDemoResource, '/init/demo') 