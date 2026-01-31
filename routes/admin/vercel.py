# -*- coding: utf-8 -*-
"""Admin Vercel 模块 - Vercel 同步和部署"""
import asyncio
import base64
import json
import os

import httpx
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse

from core.config import CONFIG, save_config, logger
from core.auth import get_account_identifier, init_account_queue
from core.deepseek import login_deepseek_via_account

from .auth import verify_admin

router = APIRouter()

# Vercel 预配置
VERCEL_TOKEN = os.getenv("VERCEL_TOKEN", "")
VERCEL_PROJECT_ID = os.getenv("VERCEL_PROJECT_ID", "")
VERCEL_TEAM_ID = os.getenv("VERCEL_TEAM_ID", "")


# ----------------------------------------------------------------------
# API 测试（通过本地 API）
# ----------------------------------------------------------------------
@router.post("/test")
async def test_api(request: Request, _: bool = Depends(verify_admin)):
    """测试 API 调用"""
    try:
        data = await request.json()
        model = data.get("model", "deepseek-chat")
        message = data.get("message", "你好")
        api_key = data.get("api_key", "")
        
        if not api_key:
            keys = CONFIG.get("keys", [])
            if not keys:
                raise HTTPException(status_code=400, detail="没有可用的 API Key")
            api_key = keys[0]
        
        host = request.headers.get("host", "localhost:5001")
        scheme = "https" if "vercel" in host.lower() else "http"
        base_url = f"{scheme}://{host}"
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{base_url}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": message}],
                    "stream": False,
                },
            )
            
            return JSONResponse(content={
                "success": response.status_code == 200,
                "status_code": response.status_code,
                "response": response.json() if response.status_code == 200 else response.text,
            })
    except Exception as e:
        logger.error(f"[test_api] 错误: {e}")
        return JSONResponse(content={"success": False, "error": str(e)})


# ----------------------------------------------------------------------
# Vercel 同步
# ----------------------------------------------------------------------
@router.post("/vercel/sync")
async def sync_to_vercel(request: Request, _: bool = Depends(verify_admin)):
    """同步配置到 Vercel 并触发重新部署"""
    try:
        data = await request.json()
        vercel_token = data.get("vercel_token", "")
        project_id = data.get("project_id", "")
        team_id = data.get("team_id", "")
        auto_validate = data.get("auto_validate", True)
        save_vercel_credentials = data.get("save_credentials", True)
        
        use_preconfig = vercel_token == "__USE_PRECONFIG__" or not vercel_token
        if use_preconfig:
            vercel_token = VERCEL_TOKEN
        if not project_id:
            project_id = VERCEL_PROJECT_ID
        if not team_id:
            team_id = VERCEL_TEAM_ID
        
        if not vercel_token or not project_id:
            raise HTTPException(status_code=400, detail="需要 Vercel Token 和 Project ID")
        
        # 自动验证账号
        validated_count = 0
        failed_accounts = []
        if auto_validate:
            accounts = CONFIG.get("accounts", [])
            for acc in accounts:
                acc_id = get_account_identifier(acc)
                if not acc.get("token", "").strip():
                    try:
                        logger.info(f"[sync_to_vercel] 自动验证账号: {acc_id}")
                        login_deepseek_via_account(acc)
                        validated_count += 1
                    except Exception as e:
                        logger.warning(f"[sync_to_vercel] 账号 {acc_id} 验证失败: {e}")
                        failed_accounts.append(acc_id)
                    await asyncio.sleep(0.5)
        
        config_json = json.dumps(CONFIG, ensure_ascii=False, separators=(",", ":"))
        config_b64 = base64.b64encode(config_json.encode("utf-8")).decode("utf-8")
        
        headers = {"Authorization": f"Bearer {vercel_token}"}
        base_url = "https://api.vercel.com"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            params = {"teamId": team_id} if team_id else {}
            env_resp = await client.get(
                f"{base_url}/v9/projects/{project_id}/env",
                headers=headers,
                params=params,
            )
            
            if env_resp.status_code != 200:
                raise HTTPException(status_code=env_resp.status_code, detail=f"获取环境变量失败: {env_resp.text}")
            
            env_vars = env_resp.json().get("envs", [])
            existing_env = None
            for env in env_vars:
                if env.get("key") == "DS2API_CONFIG_JSON":
                    existing_env = env
                    break
            
            if existing_env:
                env_id = existing_env["id"]
                update_resp = await client.patch(
                    f"{base_url}/v9/projects/{project_id}/env/{env_id}",
                    headers=headers,
                    params=params,
                    json={"value": config_b64},
                )
                if update_resp.status_code not in [200, 201]:
                    raise HTTPException(status_code=update_resp.status_code, detail=f"更新环境变量失败: {update_resp.text}")
            else:
                create_resp = await client.post(
                    f"{base_url}/v10/projects/{project_id}/env",
                    headers=headers,
                    params=params,
                    json={
                        "key": "DS2API_CONFIG_JSON",
                        "value": config_b64,
                        "type": "encrypted",
                        "target": ["production", "preview"],
                    },
                )
                if create_resp.status_code not in [200, 201]:
                    raise HTTPException(status_code=create_resp.status_code, detail=f"创建环境变量失败: {create_resp.text}")
            
            # 保存 Vercel 凭证
            saved_credentials = []
            if save_vercel_credentials and not use_preconfig:
                creds_to_save = [
                    ("VERCEL_TOKEN", vercel_token),
                    ("VERCEL_PROJECT_ID", project_id),
                ]
                if team_id:
                    creds_to_save.append(("VERCEL_TEAM_ID", team_id))
                
                for key, value in creds_to_save:
                    existing = None
                    for env in env_vars:
                        if env.get("key") == key:
                            existing = env
                            break
                    
                    if existing:
                        upd_resp = await client.patch(
                            f"{base_url}/v9/projects/{project_id}/env/{existing['id']}",
                            headers=headers,
                            params=params,
                            json={"value": value},
                        )
                        if upd_resp.status_code in [200, 201]:
                            saved_credentials.append(key)
                    else:
                        crt_resp = await client.post(
                            f"{base_url}/v10/projects/{project_id}/env",
                            headers=headers,
                            params=params,
                            json={
                                "key": key,
                                "value": value,
                                "type": "encrypted",
                                "target": ["production", "preview"],
                            },
                        )
                        if crt_resp.status_code in [200, 201]:
                            saved_credentials.append(key)
            
            # 触发重新部署
            project_resp = await client.get(
                f"{base_url}/v9/projects/{project_id}",
                headers=headers,
                params=params,
            )
            
            if project_resp.status_code == 200:
                project_data = project_resp.json()
                repo = project_data.get("link", {})
                
                if repo.get("type") == "github":
                    deploy_resp = await client.post(
                        f"{base_url}/v13/deployments",
                        headers=headers,
                        params=params,
                        json={
                            "name": project_id,
                            "project": project_id,
                            "target": "production",
                            "gitSource": {
                                "type": "github",
                                "repoId": repo.get("repoId"),
                                "ref": repo.get("productionBranch", "main"),
                            },
                        },
                    )
                    
                    if deploy_resp.status_code in [200, 201]:
                        deploy_data = deploy_resp.json()
                        result = {
                            "success": True,
                            "message": "配置已同步，正在重新部署...",
                            "deployment_url": deploy_data.get("url"),
                            "validated_accounts": validated_count,
                        }
                        if failed_accounts:
                            result["failed_accounts"] = failed_accounts
                        if saved_credentials:
                            result["saved_credentials"] = saved_credentials
                        return JSONResponse(content=result)
            
            result = {
                "success": True,
                "message": "配置已同步到 Vercel，请手动触发重新部署",
                "manual_deploy_required": True,
                "validated_accounts": validated_count,
            }
            if failed_accounts:
                result["failed_accounts"] = failed_accounts
            if saved_credentials:
                result["saved_credentials"] = saved_credentials
            return JSONResponse(content=result)
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[sync_to_vercel] 错误: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ----------------------------------------------------------------------
# 导出配置
# ----------------------------------------------------------------------
@router.get("/export")
async def export_config(_: bool = Depends(verify_admin)):
    """导出完整配置（JSON 和 Base64）"""
    config_json = json.dumps(CONFIG, ensure_ascii=False, separators=(",", ":"))
    config_b64 = base64.b64encode(config_json.encode("utf-8")).decode("utf-8")
    
    return JSONResponse(content={
        "json": config_json,
        "base64": config_b64,
    })
