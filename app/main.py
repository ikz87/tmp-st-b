from fastapi import FastAPI
from strawberry.asgi import GraphQL
# Correct import using Starlette's built-in middleware
from starlette.middleware.sessions import SessionMiddleware
from app.graphql.schema import schema
from app.routes.auth import auth_router
# from app.routes.users import users_router
from app.config import settings

app = FastAPI()

# Add Session Middleware using Starlette's built-in
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET_KEY,
    # session_cookie="session", # Optional: customize cookie name
    # max_age=14 * 24 * 60 * 60,  # Optional: set session expiry (e.g., 14 days)
    # path="/",
    # domain=None, # Optional: Set your domain in production
    # secure=True, # Optional: True if served over HTTPS (RECOMMENDED for production)
    # httponly=True, # Optional: True to prevent client-side JS access (RECOMMENDED)
    # samesite="lax" # Optional: Recommended 'lax' or 'strict'
)

# Integrar GraphQL
graphql_app = GraphQL(schema)
app.add_route("/graphql", graphql_app)

# Rutas REST
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
# app.include_router(users_router, prefix="/users", tags=["Users"])

@app.get("/")
def read_root():
    return {"message": "Welcome to SeniorThrive API"}

# Example protected route dependency
# from app.dependencies import get_current_user
# from fastapi import Depends
#
# @app.get("/protected")
# async def protected_route(user: dict = Depends(get_current_user)):
#    return {"message": "This is a protected route", "user": user}
