from fastapi import FastAPI
from strawberry.asgi import GraphQL
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware # <--- Import CORS Middleware
from app.routes.users import users_router # <--- Import the new router
from app.graphql.schema import schema
from app.routes.auth import auth_router
from app.config import settings

app = FastAPI()

# --- CORS Middleware ---
# List of allowed origins (your frontend URL)
origins = [
    "http://localhost:5173", # Your frontend development server
    "https://seniorthrivefrontend.onrender.com" # Render deployment
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, # Allows specific origins
    allow_credentials=True, # IMPORTANT: Allow cookies (needed for sessions)
    allow_methods=["*"], # Allow all standard methods (GET, POST, etc.)
    allow_headers=["*"], # Allow all headers
)
# ---------------------

# Add Session Middleware
session_cookie_params = {
    "secret_key": settings.SESSION_SECRET_KEY,
    "session_cookie": "st-session", # Optional: customize cookie name
    # max_age=..., # Optional: set expiry
    # path="/",
}

if settings.ENVIRONMENT == "production":
    print("INFO: Configuring session cookies for PRODUCTION (SameSite=None, Secure=True)")
    session_cookie_params["same_site"] = "none"
    session_cookie_params["https_only"] = True # Secure=True needed for SameSite=None
else: # development or other environments
    print("INFO: Configuring session cookies for DEVELOPMENT (SameSite=Lax, Secure=False)")
    session_cookie_params["same_site"] = "lax" # Lax is safer default for same-site/local
    session_cookie_params["https_only"] = False # Allow cookies over HTTP for local dev

app.add_middleware(SessionMiddleware, **session_cookie_params)


# Integrar GraphQL
graphql_app = GraphQL(schema)
app.add_route("/graphql", graphql_app)

# Rutas REST
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(users_router, prefix="/users", tags=["Users"]) # <--- Add the users router

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


