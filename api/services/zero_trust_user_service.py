"""零信任用户管理服务

提供零信任系统的用户管理功能，包括：
- 用户创建和注册
- 用户信息管理
- 用户状态管理
"""

import logging
import re
from datetime import UTC, datetime
from typing import Optional, List, Dict, Any

from extensions.ext_database import db
from models.zero_trust import (
    ZeroTrustUser,
    ZeroTrustUserStatus,
    ZeroTrustUserRole,
    ZeroTrustAuditLog,
)
from services.zero_trust_auth_service import ZeroTrustAuthService

logger = logging.getLogger(__name__)


class ZeroTrustUserService:
    """零信任用户管理服务"""

    @staticmethod
    def _validate_email(email: str) -> bool:
        """验证邮箱格式"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def _validate_username(username: str) -> bool:
        """验证用户名格式"""
        # 用户名长度3-50，只包含字母、数字、下划线、连字符
        pattern = r'^[a-zA-Z0-9_-]{3,50}$'
        return re.match(pattern, username) is not None

    @staticmethod
    def _validate_password(password: str) -> bool:
        """验证密码强度"""
        if len(password) < 8:
            return False
        
        # 至少包含一个大写字母、一个小写字母、一个数字
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        return has_upper and has_lower and has_digit

    @staticmethod
    def create_user(
        username: str,
        email: str,
        password: str,
        name: str,
        department: Optional[str] = None,
        role: ZeroTrustUserRole = ZeroTrustUserRole.USER
    ) -> Optional[ZeroTrustUser]:
        """创建新用户
        
        Args:
            username: 用户名
            email: 邮箱地址
            password: 密码
            name: 真实姓名
            department: 部门
            role: 用户角色
            
        Returns:
            创建成功返回用户对象，失败返回None
        """
        try:
            # 验证输入
            if not ZeroTrustUserService._validate_username(username):
                logger.error(f"用户名格式无效: {username}")
                return None
            
            if not ZeroTrustUserService._validate_email(email):
                logger.error(f"邮箱格式无效: {email}")
                return None
            
            if not ZeroTrustUserService._validate_password(password):
                logger.error("密码强度不足")
                return None
            
            # 检查用户名和邮箱是否已存在
            existing_user = db.session.query(ZeroTrustUser).filter(
                (ZeroTrustUser.username == username) | (ZeroTrustUser.email == email)
            ).first()
            
            if existing_user:
                logger.error(f"用户名或邮箱已存在: {username}, {email}")
                return None
            
            # 生成密码哈希
            salt = ZeroTrustAuthService._generate_salt()
            password_hash = ZeroTrustAuthService._hash_password(password, salt)
            
            # 创建用户
            user = ZeroTrustUser(
                username=username,
                email=email,
                password_hash=password_hash,
                salt=salt,
                name=name,
                department=department,
                role=role,
                status=ZeroTrustUserStatus.ACTIVE
            )
            
            db.session.add(user)
            db.session.commit()
            
            # 记录审计日志
            audit_log = ZeroTrustAuditLog.create_log(
                action="USER_CREATED",
                result="SUCCESS",
                user_id=user.id,
                details={
                    "username": username,
                    "email": email,
                    "name": name,
                    "department": department,
                    "role": role
                }
            )
            db.session.add(audit_log)
            db.session.commit()
            
            logger.info(f"成功创建用户: {username} ({email})")
            return user
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"创建用户失败: {str(e)}")
            return None

    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[ZeroTrustUser]:
        """根据ID获取用户"""
        return db.session.query(ZeroTrustUser).filter(
            ZeroTrustUser.id == user_id
        ).first()

    @staticmethod
    def get_user_by_username(username: str) -> Optional[ZeroTrustUser]:
        """根据用户名获取用户"""
        return db.session.query(ZeroTrustUser).filter(
            ZeroTrustUser.username == username
        ).first()

    @staticmethod
    def get_user_by_email(email: str) -> Optional[ZeroTrustUser]:
        """根据邮箱获取用户"""
        return db.session.query(ZeroTrustUser).filter(
            ZeroTrustUser.email == email
        ).first()

    @staticmethod
    def update_user(
        user_id: str,
        name: Optional[str] = None,
        department: Optional[str] = None,
        role: Optional[ZeroTrustUserRole] = None,
        status: Optional[ZeroTrustUserStatus] = None,
        operator_id: Optional[str] = None
    ) -> bool:
        """更新用户信息
        
        Args:
            user_id: 用户ID
            name: 新的姓名
            department: 新的部门
            role: 新的角色
            status: 新的状态
            operator_id: 操作者ID
            
        Returns:
            更新成功返回True，失败返回False
        """
        try:
            user = ZeroTrustUserService.get_user_by_id(user_id)
            if not user:
                logger.error(f"用户不存在: {user_id}")
                return False
            
            # 记录更新前的值
            old_values = {
                "name": user.name,
                "department": user.department,
                "role": user.role,
                "status": user.status
            }
            
            # 更新字段
            if name is not None:
                user.name = name
            if department is not None:
                user.department = department
            if role is not None:
                user.role = role
            if status is not None:
                user.status = status
            
            user.updated_at = datetime.now(UTC)
            db.session.commit()
            
            # 记录审计日志
            new_values = {
                "name": user.name,
                "department": user.department,
                "role": user.role,
                "status": user.status
            }
            
            audit_log = ZeroTrustAuditLog.create_log(
                action="USER_UPDATED",
                result="SUCCESS",
                user_id=operator_id,
                resource=user_id,
                details={
                    "old_values": old_values,
                    "new_values": new_values
                }
            )
            db.session.add(audit_log)
            db.session.commit()
            
            logger.info(f"成功更新用户: {user.username}")
            return True
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"更新用户失败: {str(e)}")
            return False

    @staticmethod
    def change_password(
        user_id: str,
        old_password: str,
        new_password: str
    ) -> bool:
        """修改用户密码
        
        Args:
            user_id: 用户ID
            old_password: 旧密码
            new_password: 新密码
            
        Returns:
            修改成功返回True，失败返回False
        """
        try:
            user = ZeroTrustUserService.get_user_by_id(user_id)
            if not user:
                logger.error(f"用户不存在: {user_id}")
                return False
            
            # 验证旧密码
            if not ZeroTrustAuthService._verify_password(old_password, user.password_hash, user.salt):
                logger.error(f"旧密码错误: {user_id}")
                return False
            
            # 验证新密码强度
            if not ZeroTrustUserService._validate_password(new_password):
                logger.error("新密码强度不足")
                return False
            
            # 生成新的密码哈希
            salt = ZeroTrustAuthService._generate_salt()
            password_hash = ZeroTrustAuthService._hash_password(new_password, salt)
            
            user.password_hash = password_hash
            user.salt = salt
            user.updated_at = datetime.now(UTC)
            
            db.session.commit()
            
            # 记录审计日志
            audit_log = ZeroTrustAuditLog.create_log(
                action="PASSWORD_CHANGED",
                result="SUCCESS",
                user_id=user_id
            )
            db.session.add(audit_log)
            db.session.commit()
            
            logger.info(f"成功修改密码: {user.username}")
            return True
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"修改密码失败: {str(e)}")
            return False

    @staticmethod
    def reset_password(
        user_id: str,
        new_password: str,
        operator_id: Optional[str] = None
    ) -> bool:
        """重置用户密码（管理员操作）
        
        Args:
            user_id: 用户ID
            new_password: 新密码
            operator_id: 操作者ID
            
        Returns:
            重置成功返回True，失败返回False
        """
        try:
            user = ZeroTrustUserService.get_user_by_id(user_id)
            if not user:
                logger.error(f"用户不存在: {user_id}")
                return False
            
            # 验证新密码强度
            if not ZeroTrustUserService._validate_password(new_password):
                logger.error("新密码强度不足")
                return False
            
            # 生成新的密码哈希
            salt = ZeroTrustAuthService._generate_salt()
            password_hash = ZeroTrustAuthService._hash_password(new_password, salt)
            
            user.password_hash = password_hash
            user.salt = salt
            user.failed_login_attempts = 0  # 重置失败次数
            user.locked_until = None  # 解除锁定
            user.updated_at = datetime.now(UTC)
            
            db.session.commit()
            
            # 记录审计日志
            audit_log = ZeroTrustAuditLog.create_log(
                action="PASSWORD_RESET",
                result="SUCCESS",
                user_id=operator_id,
                resource=user_id,
                details={"target_user": user.username}
            )
            db.session.add(audit_log)
            db.session.commit()
            
            logger.info(f"成功重置密码: {user.username}")
            return True
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"重置密码失败: {str(e)}")
            return False

    @staticmethod
    def lock_user(user_id: str, operator_id: Optional[str] = None) -> bool:
        """锁定用户"""
        return ZeroTrustUserService.update_user(
            user_id=user_id,
            status=ZeroTrustUserStatus.LOCKED,
            operator_id=operator_id
        )

    @staticmethod
    def unlock_user(user_id: str, operator_id: Optional[str] = None) -> bool:
        """解锁用户"""
        try:
            user = ZeroTrustUserService.get_user_by_id(user_id)
            if not user:
                return False
            
            user.status = ZeroTrustUserStatus.ACTIVE
            user.failed_login_attempts = 0
            user.locked_until = None
            user.updated_at = datetime.now(UTC)
            
            db.session.commit()
            
            # 记录审计日志
            audit_log = ZeroTrustAuditLog.create_log(
                action="USER_UNLOCKED",
                result="SUCCESS",
                user_id=operator_id,
                resource=user_id,
                details={"target_user": user.username}
            )
            db.session.add(audit_log)
            db.session.commit()
            
            return True
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"解锁用户失败: {str(e)}")
            return False

    @staticmethod
    def get_user_list(
        page: int = 1,
        per_page: int = 20,
        status: Optional[ZeroTrustUserStatus] = None,
        role: Optional[ZeroTrustUserRole] = None,
        search: Optional[str] = None
    ) -> Dict[str, Any]:
        """获取用户列表
        
        Args:
            page: 页码
            per_page: 每页数量
            status: 筛选状态
            role: 筛选角色
            search: 搜索关键词（用户名、邮箱、姓名）
            
        Returns:
            包含用户列表和分页信息的字典
        """
        try:
            query = db.session.query(ZeroTrustUser)
            
            # 应用筛选条件
            if status:
                query = query.filter(ZeroTrustUser.status == status)
            if role:
                query = query.filter(ZeroTrustUser.role == role)
            if search:
                search_term = f"%{search}%"
                query = query.filter(
                    (ZeroTrustUser.username.ilike(search_term)) |
                    (ZeroTrustUser.email.ilike(search_term)) |
                    (ZeroTrustUser.name.ilike(search_term))
                )
            
            # 获取总数
            total = query.count()
            
            # 分页
            offset = (page - 1) * per_page
            users = query.offset(offset).limit(per_page).all()
            
            # 转换为字典格式
            user_list = []
            for user in users:
                user_dict = {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "name": user.name,
                    "department": user.department,
                    "role": user.role,
                    "status": user.status,
                    "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
                    "failed_login_attempts": user.failed_login_attempts,
                    "locked_until": user.locked_until.isoformat() if user.locked_until else None,
                    "created_at": user.created_at.isoformat(),
                    "updated_at": user.updated_at.isoformat()
                }
                user_list.append(user_dict)
            
            return {
                "users": user_list,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "pages": (total + per_page - 1) // per_page
                }
            }
            
        except Exception as e:
            logger.error(f"获取用户列表失败: {str(e)}")
            return {
                "users": [],
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": 0,
                    "pages": 0
                }
            }

    @staticmethod
    def create_demo_users() -> List[ZeroTrustUser]:
        """创建演示用户（用于测试）"""
        demo_users_data = [
            {
                "username": "admin",
                "email": "admin@zerotrust.local",
                "password": "Admin123!",
                "name": "系统管理员",
                "department": "IT部门",
                "role": ZeroTrustUserRole.ADMIN
            },
            {
                "username": "john.doe",
                "email": "john.doe@zerotrust.local",
                "password": "User123!",
                "name": "约翰·多伊",
                "department": "产品部门",
                "role": ZeroTrustUserRole.USER
            },
            {
                "username": "jane.smith",
                "email": "jane.smith@zerotrust.local",
                "password": "Manager123!",
                "name": "简·史密斯",
                "department": "销售部门",
                "role": ZeroTrustUserRole.MANAGER
            }
        ]
        
        created_users = []
        for user_data in demo_users_data:
            user = ZeroTrustUserService.create_user(**user_data)
            if user:
                created_users.append(user)
        
        logger.info(f"创建了 {len(created_users)} 个演示用户")
        return created_users 