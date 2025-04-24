from fastapi import APIRouter

auth_router = APIRouter()

@auth_router.get("/login")
async def login():
    return {"message": "Login endpoint"}
