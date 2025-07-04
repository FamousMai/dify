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
from libs.helper import extract_remote_ip
from extensions.ext_database import db

from models.account import Account, AccountStatus
from services.account_service import AccountService, TenantService
from services.feature_service import FeatureService
from constants.languages import languages
from events.tenant_event import tenant_was_created
from datetime import UTC, datetime
from sqlalchemy import select
from sqlalchemy.orm import Session

import uuid

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


def _get_or_create_dify_account(zero_trust_user):
    """根据零信任用户信息获取或创建dify账户"""
    # 首先尝试通过邮箱查找现有账户
    with Session(db.engine) as session:
        account = session.execute(select(Account).filter_by(email=zero_trust_user.email)).scalar_one_or_none()
    
    if account:
        # 账户已存在，更新必要信息
        if account.status == AccountStatus.PENDING.value:
            account.status = AccountStatus.ACTIVE.value
            account.initialized_at = datetime.now(UTC).replace(tzinfo=None)
        
        # 更新账户名称以匹配零信任用户
        if account.name != zero_trust_user.name:
            account.name = zero_trust_user.name
        
        db.session.commit()
        
        # 确保用户有workspace
        tenants = TenantService.get_join_tenants(account)
        if not tenants:
            if FeatureService.get_system_features().is_allow_create_workspace:
                new_tenant = TenantService.create_tenant(f"{account.name}'s Workspace")
                TenantService.create_tenant_member(new_tenant, account, role="owner")
                account.current_tenant = new_tenant
                tenant_was_created.send(new_tenant)
            else:
                raise BadRequest("无法创建工作区，请联系系统管理员")
    else:
        # 创建新账户
        if not FeatureService.get_system_features().is_allow_register:
            raise BadRequest("系统不允许注册新用户")
        
        # 创建dify账户
        account = Account()
        account.id = str(uuid.uuid4())
        account.email = zero_trust_user.email
        account.name = zero_trust_user.name
        account.status = AccountStatus.ACTIVE.value
        account.initialized_at = datetime.now(UTC).replace(tzinfo=None)
        account.created_at = datetime.now(UTC).replace(tzinfo=None)
        account.updated_at = datetime.now(UTC).replace(tzinfo=None)
        
        # 设置界面语言
        account.interface_language = languages[0]  # 默认使用第一种语言
        
        db.session.add(account)
        db.session.commit()
        
        # 创建workspace
        new_tenant = TenantService.create_tenant(f"{account.name}'s Workspace")
        TenantService.create_tenant_member(new_tenant, account, role="owner")
        account.current_tenant = new_tenant
        tenant_was_created.send(new_tenant)
    
    return account


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
            redirect_url = request.args.get('redirect_url', '/apps')
            
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
    """获取Token用户信息并实现dify登录集成"""
    
    def get(self):
        """获取Token关联的用户信息并创建dify登录会话
        
        Headers:
        Authorization: Bearer <token>
        
        Returns:
        {
            "success": true,
            "user": {...},
            "dify_token": {
                "access_token": "dify_access_token",
                "refresh_token": "dify_refresh_token"
            }
        }
        """
        try:
            token = get_bearer_token()
            if not token:
                raise Unauthorized("缺少Authorization头")
            
            # 验证零信任token并获取用户信息
            zero_trust_user = ZeroTrustAuthService.verify_token(token)
            if not zero_trust_user:
                raise Unauthorized("Token无效或已过期")
            
            # 获取或创建对应的dify账户
            dify_account = _get_or_create_dify_account(zero_trust_user)
            
            # 生成dify登录token
            dify_token_pair = AccountService.login(
                account=dify_account, 
                ip_address=extract_remote_ip(request)
            )
            
            # 记录审计日志
            ZeroTrustAuthService._log_action(
                action="DIFY_LOGIN_SUCCESS",
                result="SUCCESS",
                user_id=zero_trust_user.id,
                resource="getUserTokenInfo",
                details={
                    "dify_account_id": dify_account.id,
                    "dify_account_email": dify_account.email
                }
            )
            
            return {
                "success": True,
                "user": {
                    "id": zero_trust_user.id,
                    "username": zero_trust_user.username,
                    "email": zero_trust_user.email,
                    "name": zero_trust_user.name,
                    "department": zero_trust_user.department,
                    "role": zero_trust_user.role,
                    "status": zero_trust_user.status,
                    "last_login_at": zero_trust_user.last_login_at.isoformat() if zero_trust_user.last_login_at else None,
                    "created_at": zero_trust_user.created_at.isoformat()
                },
                "dify_token": dify_token_pair.model_dump()
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


class ZeroTrustInitDemoResource(Resource):
    """演示数据初始化"""
    
    def post(self):
        """初始化演示数据
        
        Returns:
        {
            "success": true,
            "message": "演示数据初始化成功",
            "users": [...]
        }
        """
        try:
            users = ZeroTrustUserService.create_demo_users()
            
            return {
                "success": True,
                "message": "演示数据初始化成功",
                "users": [
                    {
                        "username": user.username,
                        "email": user.email,
                        "name": user.name,
                        "role": user.role
                    } for user in users
                ]
            }
            
        except Exception as e:
            logger.error(f"初始化演示数据失败: {str(e)}")
            raise BadRequest(f"初始化演示数据失败: {str(e)}")


# 注册API路由
zero_trust_api.add_resource(ZeroTrustLoginResource, '/auth/login')
zero_trust_api.add_resource(ZeroTrustTokenInfoResource, '/auth/getUserTokenInfo')
zero_trust_api.add_resource(ZeroTrustTokenVerifyResource, '/auth/verify')
zero_trust_api.add_resource(ZeroTrustLogoutResource, '/auth/logout')
zero_trust_api.add_resource(ZeroTrustInitDemoResource, '/init/demo') 