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