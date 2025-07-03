"""零信任系统数据库模型

包含零信任用户、Token和审计日志等相关模型
"""

import enum
from datetime import UTC, datetime
from typing import Optional

from sqlalchemy import JSON, func
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base
from models.types import StringUUID

from .engine import db


class ZeroTrustUserStatus(enum.StrEnum):
    """零信任用户状态枚举"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    SUSPENDED = "suspended"


class ZeroTrustUserRole(enum.StrEnum):
    """零信任用户角色枚举"""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"
    MANAGER = "manager"


class ZeroTrustTokenStatus(enum.StrEnum):
    """零信任Token状态枚举"""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ZeroTrustUser(Base):
    """零信任用户模型
    
    存储零信任系统的用户信息，独立于dify的用户系统
    """
    __tablename__ = "zero_trust_users"
    __table_args__ = (
        db.PrimaryKeyConstraint("id", name="zero_trust_user_pkey"),
        db.Index("zero_trust_user_username_idx", "username"),
        db.Index("zero_trust_user_email_idx", "email"),
        db.Index("zero_trust_user_status_idx", "status"),
        db.UniqueConstraint("username", name="unique_zero_trust_username"),
        db.UniqueConstraint("email", name="unique_zero_trust_email"),
    )

    # 基础字段
    id: Mapped[str] = mapped_column(
        StringUUID, 
        server_default=db.text("uuid_generate_v4()"),
        comment="用户唯一标识"
    )
    username: Mapped[str] = mapped_column(
        db.String(255), 
        nullable=False,
        comment="用户名"
    )
    email: Mapped[str] = mapped_column(
        db.String(255), 
        nullable=False,
        comment="邮箱地址"
    )
    
    # 认证字段
    password_hash: Mapped[str] = mapped_column(
        db.String(255), 
        nullable=False,
        comment="密码哈希值"
    )
    salt: Mapped[str] = mapped_column(
        db.String(255), 
        nullable=False,
        comment="密码盐值"
    )
    
    # 用户信息
    name: Mapped[str] = mapped_column(
        db.String(255), 
        nullable=False,
        comment="用户真实姓名"
    )
    department: Mapped[Optional[str]] = mapped_column(
        db.String(255), 
        nullable=True,
        comment="部门"
    )
    role: Mapped[ZeroTrustUserRole] = mapped_column(
        db.String(100), 
        nullable=False, 
        server_default="user",
        comment="用户角色"
    )
    
    # 状态和时间戳
    status: Mapped[ZeroTrustUserStatus] = mapped_column(
        db.String(50), 
        nullable=False, 
        server_default="active",
        comment="用户状态"
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        db.DateTime, 
        nullable=True,
        comment="最后登录时间"
    )
    last_login_ip: Mapped[Optional[str]] = mapped_column(
        db.String(45), 
        nullable=True,
        comment="最后登录IP地址"
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        db.Integer, 
        nullable=False, 
        server_default="0",
        comment="失败登录尝试次数"
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        db.DateTime, 
        nullable=True,
        comment="锁定截止时间"
    )
    
    # 元数据
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime, 
        nullable=False, 
        server_default=func.current_timestamp(),
        comment="创建时间"
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime, 
        nullable=False, 
        server_default=func.current_timestamp(),
        comment="更新时间"
    )

    def is_active(self) -> bool:
        """检查用户是否激活"""
        return self.status == ZeroTrustUserStatus.ACTIVE

    def is_locked(self) -> bool:
        """检查用户是否被锁定"""
        if self.status == ZeroTrustUserStatus.LOCKED:
            return True
        if self.locked_until and self.locked_until > datetime.now(UTC):
            return True
        return False

    def can_login(self) -> bool:
        """检查用户是否可以登录"""
        return self.is_active() and not self.is_locked()


class ZeroTrustToken(Base):
    """零信任Token模型
    
    存储零信任系统颁发的token信息
    """
    __tablename__ = "zero_trust_tokens"
    __table_args__ = (
        db.PrimaryKeyConstraint("id", name="zero_trust_token_pkey"),
        db.Index("zero_trust_token_user_id_idx", "user_id"),
        db.Index("zero_trust_token_hash_idx", "token_hash"),
        db.Index("zero_trust_token_expires_idx", "expires_at"),
        db.Index("zero_trust_token_status_idx", "status"),
        db.UniqueConstraint("token_hash", name="unique_zero_trust_token_hash"),
        db.ForeignKeyConstraint(
            ["user_id"], ["zero_trust_users.id"], 
            name="fk_zero_trust_token_user_id"
        ),
    )

    # 基础字段
    id: Mapped[str] = mapped_column(
        StringUUID, 
        server_default=db.text("uuid_generate_v4()"),
        comment="Token唯一标识"
    )
    user_id: Mapped[str] = mapped_column(
        StringUUID, 
        nullable=False,
        comment="关联的用户ID"
    )
    
    # Token信息
    token_hash: Mapped[str] = mapped_column(
        db.String(255), 
        nullable=False,
        comment="Token哈希值"
    )
    token_type: Mapped[str] = mapped_column(
        db.String(50), 
        nullable=False, 
        server_default="access_token",
        comment="Token类型"
    )
    
    # 时间相关
    expires_at: Mapped[datetime] = mapped_column(
        db.DateTime, 
        nullable=False,
        comment="过期时间"
    )
    issued_at: Mapped[datetime] = mapped_column(
        db.DateTime, 
        nullable=False, 
        server_default=func.current_timestamp(),
        comment="颁发时间"
    )
    
    # 状态和撤销
    status: Mapped[ZeroTrustTokenStatus] = mapped_column(
        db.String(50), 
        nullable=False, 
        server_default="active",
        comment="Token状态"
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        db.DateTime, 
        nullable=True,
        comment="撤销时间"
    )
    revoked_by: Mapped[Optional[str]] = mapped_column(
        StringUUID, 
        nullable=True,
        comment="撤销操作者ID"
    )
    
    # 元数据
    client_ip: Mapped[Optional[str]] = mapped_column(
        db.String(45), 
        nullable=True,
        comment="客户端IP地址"
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        db.Text, 
        nullable=True,
        comment="用户代理信息"
    )
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime, 
        nullable=False, 
        server_default=func.current_timestamp(),
        comment="创建时间"
    )
    updated_at: Mapped[datetime] = mapped_column(
        db.DateTime, 
        nullable=False, 
        server_default=func.current_timestamp(),
        comment="更新时间"
    )

    def is_valid(self) -> bool:
        """检查Token是否有效"""
        if self.status != ZeroTrustTokenStatus.ACTIVE:
            return False
        if self.expires_at < datetime.now(UTC):
            return False
        return True

    def is_expired(self) -> bool:
        """检查Token是否过期"""
        return self.expires_at < datetime.now(UTC)

    def revoke(self, revoked_by: Optional[str] = None):
        """撤销Token"""
        self.status = ZeroTrustTokenStatus.REVOKED
        self.revoked_at = datetime.now(UTC)
        self.revoked_by = revoked_by


class ZeroTrustAuditLog(Base):
    """零信任审计日志模型
    
    记录零信任系统的所有操作审计日志
    """
    __tablename__ = "zero_trust_audit_logs"
    __table_args__ = (
        db.PrimaryKeyConstraint("id", name="zero_trust_audit_log_pkey"),
        db.Index("zero_trust_audit_log_user_id_idx", "user_id"),
        db.Index("zero_trust_audit_log_action_idx", "action"),
        db.Index("zero_trust_audit_log_created_at_idx", "created_at"),
        db.Index("zero_trust_audit_log_ip_idx", "ip_address"),
        db.ForeignKeyConstraint(
            ["user_id"], ["zero_trust_users.id"], 
            name="fk_zero_trust_audit_log_user_id"
        ),
    )

    # 基础字段
    id: Mapped[str] = mapped_column(
        StringUUID, 
        server_default=db.text("uuid_generate_v4()"),
        comment="日志唯一标识"
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        StringUUID, 
        nullable=True,
        comment="操作用户ID"
    )
    
    # 操作信息
    action: Mapped[str] = mapped_column(
        db.String(100), 
        nullable=False,
        comment="操作类型"
    )
    resource: Mapped[Optional[str]] = mapped_column(
        db.String(255), 
        nullable=True,
        comment="操作资源"
    )
    result: Mapped[str] = mapped_column(
        db.String(50), 
        nullable=False,
        comment="操作结果"
    )
    
    # 请求信息
    ip_address: Mapped[Optional[str]] = mapped_column(
        db.String(45), 
        nullable=True,
        comment="客户端IP地址"
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        db.Text, 
        nullable=True,
        comment="用户代理信息"
    )
    
    # 详细信息
    details: Mapped[Optional[dict]] = mapped_column(
        JSON, 
        nullable=True,
        comment="操作详细信息"
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        db.Text, 
        nullable=True,
        comment="错误信息"
    )
    
    # 时间戳
    created_at: Mapped[datetime] = mapped_column(
        db.DateTime, 
        nullable=False, 
        server_default=func.current_timestamp(),
        comment="创建时间"
    )

    @classmethod
    def create_log(
        cls,
        action: str,
        result: str,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[dict] = None,
        error_message: Optional[str] = None
    ) -> "ZeroTrustAuditLog":
        """创建审计日志"""
        log = cls(
            user_id=user_id,
            action=action,
            resource=resource,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            error_message=error_message
        )
        return log 