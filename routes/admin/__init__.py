# -*- coding: utf-8 -*-
"""Admin 路由模块 - 合并所有子模块路由"""
from fastapi import APIRouter

from .auth import router as auth_router, verify_admin, ADMIN_KEY
from .config import router as config_router
from .accounts import router as accounts_router
from .vercel import router as vercel_router

# 创建主路由
router = APIRouter(prefix="/admin", tags=["admin"])

# 包含所有子路由
router.include_router(auth_router)
router.include_router(config_router)
router.include_router(accounts_router)
router.include_router(vercel_router)

# 导出常用依赖
__all__ = ["router", "verify_admin", "ADMIN_KEY"]
