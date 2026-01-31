# -*- coding: utf-8 -*-
"""Admin 认证模块 - JWT 和登录相关"""
import base64
import os
import time
import hashlib
import hmac

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from core.config import logger

router = APIRouter()
security = HTTPBearer(auto_error=False)

# Admin Key 验证
ADMIN_KEY = os.getenv("DS2API_ADMIN_KEY", "")

# JWT 配置
JWT_SECRET = os.getenv("DS2API_JWT_SECRET", ADMIN_KEY or "ds2api-default-secret")
JWT_EXPIRE_HOURS = int(os.getenv("DS2API_JWT_EXPIRE_HOURS", "24"))


# ----------------------------------------------------------------------
# JWT 工具函数（轻量实现，无需额外依赖）
# ----------------------------------------------------------------------
def _b64_encode(data: bytes) -> str:
    """Base64 URL 安全编码"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64_decode(data: str) -> bytes:
    """Base64 URL 安全解码"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)

def create_jwt_token(expire_hours: int = None) -> str:
    """创建 JWT Token"""
    import json
    
    if expire_hours is None:
        expire_hours = JWT_EXPIRE_HOURS
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iat": int(time.time()),
        "exp": int(time.time()) + (expire_hours * 3600),
        "role": "admin"
    }
    
    header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).digest()
    signature_b64 = _b64_encode(signature)
    
    return f"{message}.{signature_b64}"

def verify_jwt_token(token: str) -> dict:
    """验证 JWT Token，返回 payload 或抛出异常"""
    import json
    
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # 验证签名
        message = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).digest()
        actual_sig = _b64_decode(signature_b64)
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("Invalid signature")
        
        # 解析 payload
        payload = json.loads(_b64_decode(payload_b64))
        
        # 验证过期时间
        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        
        return payload
    except Exception as e:
        raise ValueError(f"Token verification failed: {str(e)}")


# ----------------------------------------------------------------------
# 登录端点
# ----------------------------------------------------------------------
@router.post("/login")
async def admin_login(request: Request):
    """管理员登录，返回 JWT Token"""
    try:
        data = await request.json()
    except:
        data = {}
    
    admin_key = data.get("admin_key", "")
    expire_hours = data.get("expire_hours", JWT_EXPIRE_HOURS)
    
    # 开发模式：如果没有配置 ADMIN_KEY，允许任意登录
    if not ADMIN_KEY:
        logger.warning("[admin_login] 开发模式：未配置 ADMIN_KEY，允许任意登录")
        token = create_jwt_token(expire_hours)
        return JSONResponse(content={
            "success": True,
            "token": token,
            "expires_in": expire_hours * 3600,
            "warning": "开发模式 - 未配置 ADMIN_KEY"
        })
    
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")
    
    token = create_jwt_token(expire_hours)
    return JSONResponse(content={
        "success": True,
        "token": token,
        "expires_in": expire_hours * 3600
    })


@router.get("/verify")
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证当前 Token 是否有效"""
    if not credentials:
        raise HTTPException(status_code=401, detail="No credentials provided")
    
    token = credentials.credentials
    try:
        payload = verify_jwt_token(token)
        return JSONResponse(content={
            "valid": True,
            "expires_at": payload.get("exp"),
            "remaining_seconds": max(0, payload.get("exp", 0) - int(time.time()))
        })
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


def verify_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证 Admin 权限（支持 JWT 和直接 admin key）"""
    # 开发模式：如果没有配置 ADMIN_KEY，允许所有操作
    if not ADMIN_KEY:
        return True
    
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    token = credentials.credentials
    
    # 尝试 JWT 验证
    try:
        verify_jwt_token(token)
        return True
    except ValueError:
        pass
    
    # 尝试直接 admin key
    if token == ADMIN_KEY:
        return True
    
    raise HTTPException(status_code=401, detail="Invalid credentials")
