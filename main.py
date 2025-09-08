import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlmodel import SQLModel
from logging_lib import RouterLoggingMiddleware, get_json_logger
import secrets

logger = get_json_logger("main")


# Define application
def get_application() -> FastAPI:
    application = FastAPI(title="FastAPI Logging", debug=True)

    application.add_middleware(
        RouterLoggingMiddleware,
        logger=logger
    )

    return application

# Initialize application
app = get_application()

# Define SQLModel for testing
class User(SQLModel):
    first_name: str
    last_name: str
    email: str

class LoginIn(BaseModel):
    username: str
    password: str

@app.get("/", response_model=User)
def root():
    return User(first_name="John", last_name="Doe", email="jon@doe.com")

# POST /login separado
@app.post("/login")
async def login(body: LoginIn):
    if body.username == "admin" and body.password == "admin":
        token = secrets.token_urlsafe(32)
        return {"status": "sucesso", "token": token}
    raise HTTPException(status_code=500, detail="falha de autenticação")


def root():
    user = User(
        first_name="John",
        last_name="Doe",
        email="jon@doe.com"
    )
    return user

### response example
###{"asctime": "2025-09-08 08:47:49,796", "levelname": "INFO", "X-API-TRACE-ID": "b0a398ab-0ac8-4b09-8b3e-ed5161dfd969", "request": {"method": "GET", "path": "/", "ip": "127.0.0.1", "headers": {"host": "127.0.0.1:8000", "connection": "keep-alive", "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"Linux\"", "upgrade-insecure-requests": "1", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "sec-fetch-site": "none", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1", "sec-fetch-dest": "document", "accept-encoding": "gzip, deflate, br, zstd", "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"}}, "response": {"status": "successful", "status_code": 200, "time_taken": "0.0050s", "body": {"first_name": "John", "last_name": "Doe", "email": "jon@doe.com"}}}