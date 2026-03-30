from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import json

# 匯入 WebAuthn 相關套件 
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,  # <--- 新增這一行
)

app = FastAPI()

# 設定模板目錄指向我們剛剛建立的 index.html
templates = Jinja2Templates(directory="phase3/app/templates")

# 模擬資料庫：儲存使用者的公鑰憑證與目前的挑戰碼
db = {
    "users": {},      # 格式: { "username": { "id": bytes, "credentials": [憑證資料] } }
    "challenges": {}  # 格式: { "username": "目前的_challenge_字串" }
}

# WebAuthn 基本設定
RP_ID = "localhost"
RP_NAME = "Cryptography Engineering Phase 3"
ORIGIN = "http://localhost:8000"

@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """提供前端網頁"""
    return templates.TemplateResponse("index.html", {"request": request})

#註冊流程 

@app.get("/api/register/options")
async def register_options(username: str):
    """步驟 1：生成註冊選項與 Challenge"""
    # 使用者嘗試註冊已經存在的帳號
    if username in db["users"]:
        raise HTTPException(status_code=400, detail="The user tries to register with a username that is already registered.")

    # 產生註冊選項
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=username.encode(), # 簡單起見，直接用 username 轉 bytes 當作 user_id
        user_name=username,
    )
    
    # 儲存挑戰碼，稍後驗證需要用到
    db["challenges"][username] = options.challenge

    # 將 WebAuthn 物件轉為 JSON 格式回傳給前端
    # 為了配合前端 data.publicKey 的讀取方式，我們包裝在一層 JSON 中
    return {"publicKey": json.loads(options_to_json(options))}


@app.post("/api/register/verify")
async def register_verify(username: str, request: Request):
    """步驟 2：驗證瀏覽器回傳的註冊簽章"""
    credential_data = await request.json()
    expected_challenge = db["challenges"].get(username)

    if not expected_challenge:
        raise HTTPException(status_code=400, detail="Challenge not found. Please try again.")

    try:
        # 驗證註冊資料
        verification = verify_registration_response(
            credential=credential_data,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )
        
        # 使用者的公鑰憑證存入資料庫
        db["users"][username] = {
            "id": username.encode(),
            "credentials": [
                {
                    "id": verification.credential_id,
                    "public_key": verification.credential_public_key,
                    "sign_count": verification.sign_count,
                    "transports": credential_data.get("response", {}).get("transports", []),
                }
            ]
        }
        
        # 清除用過的挑戰碼
        del db["challenges"][username]
        return {"status": "ok"}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")


#登入流程 

@app.get("/api/login/options")
async def login_options(username: str):
    """步驟 1：生成登入選項與 Challenge"""
    # 用者嘗試登入一個不存在的帳號
    if username not in db["users"]:
        raise HTTPException(status_code=400, detail="The user tries to log in with a username that is not registered.")

    # 取出使用者之前註冊的憑證 ID
    user_credentials = db["users"][username]["credentials"]
    allow_credentials = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,  # <--- 修改這裡
            id=cred["id"]
        ) for cred in user_credentials
    ]
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
    )

    # 儲存挑戰碼
    db["challenges"][username] = options.challenge
    return {"publicKey": json.loads(options_to_json(options))}


@app.post("/api/login/verify")
async def login_verify(username: str, request: Request):
    """步驟 2：驗證瀏覽器回傳的登入簽章"""
    assertion_data = await request.json()
    expected_challenge = db["challenges"].get(username)

    if not expected_challenge:
        raise HTTPException(status_code=400, detail="Challenge not found.")

    user_credentials = db["users"].get(username, {}).get("credentials", [])
    if not user_credentials:
        raise HTTPException(status_code=400, detail="User credentials not found.")

    # 找出對應的公鑰
    credential = next((c for c in user_credentials if c["id"] == assertion_data.get("rawId", assertion_data.get("id"))), user_credentials[0])

    try:
        # 驗證登入簽章 
        verification = verify_authentication_response(
            credential=assertion_data,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=credential["public_key"],
            credential_current_sign_count=credential["sign_count"],
        )

        # 更新簽章計數器 
        credential["sign_count"] = verification.new_sign_count
        
        # 清除用過的挑戰碼
        del db["challenges"][username]
        return {"status": "ok"}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Login failed: {str(e)}")