import time
import uuid
import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, EmailStr
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig


app = FastAPI()

# Firebase Realtime Database temel URL'niz
FIREBASE_DB_URL = "https://gorevler-543db-default-rtdb.firebaseio.com"

# Mail konfigürasyonu
from fastapi_mail import ConnectionConfig

conf = ConnectionConfig(
    MAIL_USERNAME="nurhakaydin5@gmail.com",
    MAIL_PASSWORD="hzih nfya wdvn jvge",  # Uygulama şifreni buraya tam, boşluksuz yapıştır
    MAIL_FROM="nurhakaydin5@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)



fast_mail = FastMail(conf)

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

async def get_user_by_email(email: str):
    """Firebase'den email ile kullanıcı bul"""
    async with httpx.AsyncClient() as client:
        res = await client.get(f"{FIREBASE_DB_URL}/users.json")
        if res.status_code != 200:
            raise HTTPException(status_code=500, detail="Kullanıcılar yüklenemedi")
        users = res.json() or {}
        for key, user in users.items():
            if user.get("email") == email:
                return {"key": key, **user}
    return None

async def save_token(token: str, email: str):
    """Firebase'e token kaydet"""
    now = int(time.time())
    expires_at = now + 3600  # 1 saat geçerli
    data = {
        token: {
            "email": email,
            "created_at": now,
            "expires_at": expires_at,
            "used": False,
        }
    }
    async with httpx.AsyncClient() as client:
        res = await client.patch(f"{FIREBASE_DB_URL}/password_reset_tokens.json", json=data)
        if res.status_code != 200:
            raise HTTPException(status_code=500, detail="Token kaydedilemedi")

async def send_reset_email(email: str, token: str):
    """Şifre sıfırlama maili gönder"""
    reset_link = f"http://yourfrontend.com/reset-password?token={token}"  # Frontend linki buraya
    message = MessageSchema(
        subject="Şifre Sıfırlama Talebi",
        recipients=[email],
        body=f"Şifrenizi sıfırlamak için lütfen aşağıdaki linke tıklayın:\n{reset_link}\nLink 1 saat geçerlidir.",
        subtype="plain"
    )
    await fast_mail.send_message(message)

@app.post("/password-reset/request")
async def password_reset_request(data: PasswordResetRequest, background_tasks: BackgroundTasks):
    user = await get_user_by_email(data.email)
    if not user:
        raise HTTPException(status_code=404, detail="Email adresi kayıtlı değil")

    token = str(uuid.uuid4())
    await save_token(token, data.email)

    background_tasks.add_task(send_reset_email, data.email, token)
    return {"detail": "Şifre sıfırlama maili gönderildi"}

@app.post("/password-reset/confirm")
async def password_reset_confirm(data: PasswordResetConfirm):
    token = data.token
    new_password = data.new_password

    # Token kontrolü
    async with httpx.AsyncClient() as client:
        res = await client.get(f"{FIREBASE_DB_URL}/password_reset_tokens/{token}.json")
        if res.status_code != 200 or not res.json():
            raise HTTPException(status_code=400, detail="Geçersiz token")

        token_data = res.json()

    if token_data.get("used"):
        raise HTTPException(status_code=400, detail="Token zaten kullanılmış")

    now = int(time.time())
    if now > token_data.get("expires_at", 0):
        raise HTTPException(status_code=400, detail="Token süresi dolmuş")

    email = token_data.get("email")
    user = await get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")

    # Kullanıcının şifresini güncelle (burada kullanıcı firebase key'i ile)
    user_key = user["key"]
    update_data = {"sifre": new_password}
    async with httpx.AsyncClient() as client:
        res = await client.patch(f"{FIREBASE_DB_URL}/users/{user_key}.json", json=update_data)
        if res.status_code != 200:
            raise HTTPException(status_code=500, detail="Şifre güncellenemedi")

    # Token'ı kullanılmış olarak işaretle
    async with httpx.AsyncClient() as client:
        res = await client.patch(
            f"{FIREBASE_DB_URL}/password_reset_tokens/{token}.json",
            json={"used": True}
        )
        if res.status_code != 200:
            raise HTTPException(status_code=500, detail="Token güncellenemedi")

    return {"detail": "Şifre başarıyla güncellendi"}



