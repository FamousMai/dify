"""零信任认证服务

提供零信任系统的认证相关功能，包括：
- 用户登录验证
- Token生成和验证
- 审计日志记录
"""

import hashlib
import hmac
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Optional

import jwt
from flask import request

from extensions.ext_database import db
from models.zero_trust import (
    ZeroTrustAuditLog,
    ZeroTrustToken,
    ZeroTrustTokenStatus,
    ZeroTrustUser,
    ZeroTrustUserStatus,
)

# 零信任系统配置
ZERO_TRUST_JWT_SECRET = "zero-trust-jwt-secret-key-for-development"  # 实际应用中应该从环境变量获取
ZERO_TRUST_TOKEN_EXPIRE_MINUTES = 30
ZERO_TRUST_REFRESH_TOKEN_EXPIRE_DAYS = 7
ZERO_TRUST_MAX_LOGIN_ATTEMPTS = 5
ZERO_TRUST_LOCKOUT_DURATION_MINUTES = 30

logger = logging.getLogger(__name__)


class ZeroTrustAuthService:
    """零信任认证服务"""

    @staticmethod
    def _log_action(
        action: str,
        result: str,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        error_message: Optional[str] = None
    ) -> None:
        """记录审计日志"""
        try:
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get('User-Agent') if request else None
            
            audit_log = ZeroTrustAuditLog.create_log(
                action=action,
                result=result,
                user_id=user_id,
                resource=resource,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details,
                error_message=error_message
            )
            
            db.session.add(audit_log)
            db.session.commit()
            
            # 输出到控制台（用于调试）
            logger.info(f"[零信任审计] {action} - {result} - 用户:{user_id} - IP:{ip_address}")
            
        except Exception as e:
            logger.error(f"记录审计日志失败: {str(e)}")

    @staticmethod
    def _generate_salt() -> str:
        """生成随机盐值"""
        return secrets.token_hex(32)

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """使用PBKDF2算法哈希密码"""
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256',  # 哈希算法
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000,  # 迭代次数
            64  # 哈希长度
        )
        return hash_bytes.hex()

    @staticmethod
    def _verify_password(password: str, password_hash: str, salt: str) -> bool:
        """验证密码"""
        return hmac.compare_digest(
            ZeroTrustAuthService._hash_password(password, salt),
            password_hash
        )

    @staticmethod
    def _generate_jwt_token(user_id: str, expires_in_minutes: int = ZERO_TRUST_TOKEN_EXPIRE_MINUTES) -> str:
        """生成JWT Token"""
        payload = {
            'user_id': user_id,
            'exp': datetime.now(UTC) + timedelta(minutes=expires_in_minutes),
            'iat': datetime.now(UTC),
            'iss': 'zero-trust-system',
            'aud': 'dify-api'
        }
        
        return jwt.encode(payload, ZERO_TRUST_JWT_SECRET, algorithm='HS256')

    @staticmethod
    def _verify_jwt_token(token: str) -> Optional[dict[str, Any]]:
        """验证JWT Token"""
        try:
            payload = jwt.decode(
                token, 
                ZERO_TRUST_JWT_SECRET, 
                algorithms=['HS256'],
                audience='dify-api',
                issuer='zero-trust-system'
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token已过期")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token验证失败: {str(e)}")
            return None

    @staticmethod
    def _hash_token(token: str) -> str:
        """对Token进行哈希处理，用于数据库存储"""
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    @staticmethod
    def authenticate_user(username: str, password: str) -> Optional[ZeroTrustUser]:
        """用户认证
        
        Args:
            username: 用户名或邮箱
            password: 密码
            
        Returns:
            认证成功返回用户对象，失败返回None
        """
        # 查找用户（支持用户名或邮箱登录）
        user = db.session.query(ZeroTrustUser).filter(
            (ZeroTrustUser.username == username) | (ZeroTrustUser.email == username)
        ).first()
        
        if not user:
            ZeroTrustAuthService._log_action(
                action="LOGIN_ATTEMPT",
                result="FAILED",
                resource=username,
                error_message="用户不存在"
            )
            return None
        
        # 检查用户状态
        if not user.can_login():
            ZeroTrustAuthService._log_action(
                action="LOGIN_ATTEMPT",
                result="FAILED",
                user_id=user.id,
                resource=username,
                error_message=f"用户状态不允许登录: {user.status}"
            )
            return None
        
        # 验证密码
        if not ZeroTrustAuthService._verify_password(password, user.password_hash, user.salt):
            # 增加失败登录次数
            user.failed_login_attempts += 1
            
            # 如果失败次数过多，锁定账户
            if user.failed_login_attempts >= ZERO_TRUST_MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.now() + timedelta(minutes=ZERO_TRUST_LOCKOUT_DURATION_MINUTES)
                ZeroTrustAuthService._log_action(
                    action="ACCOUNT_LOCKED",
                    result="SUCCESS",
                    user_id=user.id,
                    details={"reason": "too_many_failed_attempts", "attempts": user.failed_login_attempts}
                )
            
            db.session.commit()
            
            ZeroTrustAuthService._log_action(
                action="LOGIN_ATTEMPT",
                result="FAILED",
                user_id=user.id,
                resource=username,
                error_message="密码错误",
                details={"failed_attempts": user.failed_login_attempts}
            )
            return None
        
        # 登录成功，重置失败次数
        user.failed_login_attempts = 0
        user.last_login_at = datetime.now()
        user.last_login_ip = request.remote_addr if request else None
        user.locked_until = None
        
        db.session.commit()
        
        ZeroTrustAuthService._log_action(
            action="LOGIN_SUCCESS",
            result="SUCCESS",
            user_id=user.id,
            resource=username
        )
        
        return user

    @staticmethod
    def generate_token(user: ZeroTrustUser) -> str:
        """为用户生成访问Token
        
        Args:
            user: 用户对象
            
        Returns:
            JWT Token字符串
        """
        try:
            # 生成JWT Token
            jwt_token = ZeroTrustAuthService._generate_jwt_token(user.id)
            
            # 保存Token到数据库
            token_hash = ZeroTrustAuthService._hash_token(jwt_token)
            token_record = ZeroTrustToken(
                user_id=user.id,
                token_hash=token_hash,
                expires_at=datetime.now() + timedelta(minutes=ZERO_TRUST_TOKEN_EXPIRE_MINUTES),
                client_ip=request.remote_addr if request else None,
                user_agent=request.headers.get('User-Agent') if request else None
            )
            
            db.session.add(token_record)
            db.session.commit()
            
            ZeroTrustAuthService._log_action(
                action="TOKEN_GENERATED",
                result="SUCCESS",
                user_id=user.id,
                details={"token_id": token_record.id, "expires_at": token_record.expires_at.isoformat()}
            )
            
            return jwt_token
            
        except Exception as e:
            ZeroTrustAuthService._log_action(
                action="TOKEN_GENERATION",
                result="FAILED",
                user_id=user.id,
                error_message=str(e)
            )
            raise

    @staticmethod
    def verify_token(token: str) -> Optional[ZeroTrustUser]:
        """验证Token并返回用户信息
        
        Args:
            token: JWT Token字符串
            
        Returns:
            验证成功返回用户对象，失败返回None
        """
        try:
            # 验证JWT Token
            payload = ZeroTrustAuthService._verify_jwt_token(token)
            if not payload:
                return None
            
            user_id = payload.get('user_id')
            if not user_id:
                return None
            
            # 检查Token是否在数据库中存在且有效
            token_hash = ZeroTrustAuthService._hash_token(token)
            token_record = db.session.query(ZeroTrustToken).filter(
                ZeroTrustToken.token_hash == token_hash,
                ZeroTrustToken.user_id == user_id,
                ZeroTrustToken.status == ZeroTrustTokenStatus.ACTIVE
            ).first()
            
            if not token_record or not token_record.is_valid():
                ZeroTrustAuthService._log_action(
                    action="TOKEN_VERIFICATION",
                    result="FAILED",
                    user_id=user_id,
                    error_message="Token无效或已过期"
                )
                return None
            
            # 获取用户信息
            user = db.session.query(ZeroTrustUser).filter(
                ZeroTrustUser.id == user_id,
                ZeroTrustUser.status == ZeroTrustUserStatus.ACTIVE
            ).first()
            
            if not user:
                ZeroTrustAuthService._log_action(
                    action="TOKEN_VERIFICATION",
                    result="FAILED",
                    user_id=user_id,
                    error_message="用户不存在或已禁用"
                )
                return None
            
            ZeroTrustAuthService._log_action(
                action="TOKEN_VERIFICATION",
                result="SUCCESS",
                user_id=user.id,
                details={"token_id": token_record.id}
            )
            
            return user
            
        except Exception as e:
            ZeroTrustAuthService._log_action(
                action="TOKEN_VERIFICATION",
                result="FAILED",
                error_message=str(e)
            )
            return None

    @staticmethod
    def revoke_token(token: str, revoked_by: Optional[str] = None) -> bool:
        """撤销Token
        
        Args:
            token: 要撤销的Token
            revoked_by: 撤销操作的执行者
            
        Returns:
            撤销成功返回True，失败返回False
        """
        try:
            token_hash = ZeroTrustAuthService._hash_token(token)
            token_record = db.session.query(ZeroTrustToken).filter(
                ZeroTrustToken.token_hash == token_hash
            ).first()
            
            if not token_record:
                return False
            
            token_record.revoke(revoked_by)
            db.session.commit()
            
            ZeroTrustAuthService._log_action(
                action="TOKEN_REVOKED",
                result="SUCCESS",
                user_id=token_record.user_id,
                details={"token_id": token_record.id, "revoked_by": revoked_by}
            )
            
            return True
            
        except Exception as e:
            ZeroTrustAuthService._log_action(
                action="TOKEN_REVOCATION",
                result="FAILED",
                error_message=str(e)
            )
            return False

    @staticmethod
    def clean_expired_tokens() -> int:
        """清理过期的Token
        
        Returns:
            清理的Token数量
        """
        try:
            expired_tokens = db.session.query(ZeroTrustToken).filter(
                ZeroTrustToken.expires_at < datetime.now(),
                ZeroTrustToken.status == ZeroTrustTokenStatus.ACTIVE
            ).all()
            
            count = 0
            for token in expired_tokens:
                token.status = ZeroTrustTokenStatus.EXPIRED
                count += 1
            
            db.session.commit()
            
            ZeroTrustAuthService._log_action(
                action="TOKENS_CLEANUP",
                result="SUCCESS",
                details={"cleaned_count": count}
            )
            
            return count
            
        except Exception as e:
            ZeroTrustAuthService._log_action(
                action="TOKENS_CLEANUP",
                result="FAILED",
                error_message=str(e)
            )
            return 0

    @staticmethod
    def get_user_token_info(token: str) -> Optional[dict[str, Any]]:
        """获取Token关联的用户信息（模拟外部API）
        
        Args:
            token: JWT Token
            
        Returns:
            用户信息字典或None
        """
        user = ZeroTrustAuthService.verify_token(token)
        if not user:
            return None
        
        ZeroTrustAuthService._log_action(
            action="USER_INFO_REQUEST",
            result="SUCCESS",
            user_id=user.id,
            resource="getUserTokenInfo"
        )
        
        return {
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