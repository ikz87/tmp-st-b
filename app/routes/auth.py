import httpx
import secrets
import hashlib
import base64
from urllib.parse import urlencode
from fastapi import APIRouter, Request, HTTPException, Depends, Form, status # Added Form, status
from fastapi.responses import RedirectResponse
from jose import jwt, JWTError
# from jose.utils import base64url_decode # Not used in current code, can remove if not needed elsewhere
from pydantic import EmailStr # Added for email validation
from app.config import settings
from app.dependencies import get_optional_current_user, get_current_user # Added get_current_user

# --- Create the router FIRST ---
auth_router = APIRouter()
# -----------------------------

# In-memory cache for JWKS (in production, consider a more robust cache like Redis)
jwks_cache = None

async def get_jwks():
    """Fetches and caches JWKS from Auth0."""
    global jwks_cache
    if jwks_cache:
        return jwks_cache
    try:
        async with httpx.AsyncClient() as client:
            jwks_url = f"https://{settings.AUTH0_DOMAIN}/.well-known/jwks.json"
            response = await client.get(jwks_url)
            response.raise_for_status()
            jwks_cache = response.json()
            return jwks_cache
    except httpx.HTTPStatusError as e:
        print(f"Error fetching JWKS: {e}")
        raise HTTPException(status_code=500, detail="Could not fetch JWKS from Auth0")
    except Exception as e:
        print(f"Unexpected error fetching JWKS: {e}")
        raise HTTPException(status_code=500, detail="Internal server error fetching JWKS")


async def validate_token(token: str):
    """Validates the ID token using Auth0's JWKS."""
    try:
        jwks = await get_jwks()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=settings.AUTH0_CLIENT_ID, # ID token audience is Client ID
                issuer=f"https://{settings.AUTH0_DOMAIN}/"
            )
            return payload
        raise JWTError("Unable to find appropriate key")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token is expired")
    except jwt.JWTClaimsError as e:
        print(f"JWT Claims Error: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid claims: {e}")
    except JWTError as e:
        print(f"JWT Error: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    except Exception as e:
        print(f"Unexpected error during token validation: {e}")
        raise HTTPException(status_code=500, detail="Error validating token")


# --- ROPG Endpoint ---
@auth_router.post("/token-login")
async def token_login(
    request: Request,
    email: EmailStr = Form(...),
    password: str = Form(...)
):
    """
    Handles login via email/password directly using ROPG.
    **WARNING: This flow has security implications and bypasses Universal Login features.**
    """
    token_url = f"https://{settings.AUTH0_DOMAIN}/oauth/token"
    token_payload = {
        "grant_type": "password", # Use Resource Owner Password Grant
        "client_id": settings.AUTH0_CLIENT_ID,
        "client_secret": settings.AUTH0_CLIENT_SECRET, # Required for ROPG unless using private_key_jwt
        "username": email, # Auth0 uses 'username' field for email in ROPG
        "password": password,
        "audience": settings.AUTH0_AUDIENCE,
        "realm": "Username-Password-Authentication",
        "scope": "openid profile email offline_access", # Request necessary scopes
    }

    
    async with httpx.AsyncClient() as client:
        token_response = None # Initialize outside try
        try:
            token_response = await client.post(token_url, data=token_payload)

            # Check for specific ROPG errors *before* raise_for_status
            if token_response.status_code in [401, 403]:
                 error_detail = "Invalid email or password."
                 try:
                     error_data = token_response.json()
                     if error_data.get("error") == "invalid_grant":
                         error_detail = "Invalid email or password."
                     elif error_data.get("error_description"):
                          print(f"Auth0 ROPG Error Desc: {error_data.get('error_description')}")
                          # Avoid reflecting detailed Auth0 errors directly to frontend usually
                          # error_detail = error_data.get('error_description')
                 except Exception:
                     pass # Ignore JSON parsing errors if body isn't JSON
                 # Raise the specific 401 error
                 raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=error_detail
                 )

            # Raise exceptions for other non-2xx responses (400, 404, 5xx etc.)
            token_response.raise_for_status()
            token_data = token_response.json()

        # Catch specific HTTP errors from httpx *after* handling 401/403
        except httpx.HTTPStatusError as e:
            # This will now catch errors other than the 401/403 we handled above
            print(f"Token exchange failed (ROPG): {e.response.status_code} - {e.response.text if e.response else 'No response text'}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login failed during token exchange.")

        # Catch ONLY unexpected errors (network issues, programming errors)
        # DO NOT catch HTTPException here, let it propagate
        except Exception as e:
            # Check if it's an HTTPException we already raised, if so, re-raise it
            if isinstance(e, HTTPException):
                raise e
            # Otherwise, it's an unexpected internal error
            print(f"Unexpected error during token exchange (ROPG): {type(e).__name__} - {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during login.")


    id_token = token_data.get("id_token")
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")

    if not id_token:
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="ID token not found in Auth0 response.")

    # Validate the ID token (same function as before)
    try:
        user_profile = await validate_token(id_token)
    except HTTPException as e:
        raise e # Re-raise validation errors
    except Exception as e:
        print(f"Unexpected error during token validation (ROPG): {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to validate token after login.")

    # --- User Persistence (Optional but Recommended - Same as callback) ---
    # Example (requires Prisma setup):
    # from app.prisma import db # Make sure prisma client is initialized
    # try:
    #     user = await db.user.upsert(
    #         where={'email': user_profile.get('email')},
    #         data={
    #             'create': {
    #                 'email': user_profile.get('email'),
    #                 'name': user_profile.get('name'),
    #                 'auth0_sub': user_profile.get('sub'),
    #             },
    #             'update': {
    #                 'name': user_profile.get('name'),
    #                 'auth0_sub': user_profile.get('sub'),
    #             }
    #         }
    #     )
    # except Exception as db_error:
    #     print(f"Database error during user upsert: {db_error}")
    #     # Decide if this should prevent login or just be logged
    # ----------------------------------------------------

    # Store user info in the session (Same as callback)
    request.session["user"] = user_profile
    request.session["id_token"] = id_token
    # Decide if you need to store access/refresh tokens server-side

    # No redirect needed, just return success (e.g., user profile)
    # The session cookie is automatically set by the middleware
    return {"message": "Login successful", "user": user_profile}


# --- Redirect Login Endpoint (for social or fallback) ---
@auth_router.get("/login")
async def login(request: Request, user: dict | None = Depends(get_optional_current_user)):
    """
    Initiates the Auth0 login flow by redirecting the user to Auth0.
    Generates state and PKCE parameters. Can be used for social logins.
    """
    if user:
        # Already logged in, redirect to frontend home or dashboard
        return RedirectResponse(url=settings.APP_BASE_URL)

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    request.session["state"] = state

    # Generate PKCE parameters
    code_verifier = secrets.token_urlsafe(64)
    request.session["code_verifier"] = code_verifier
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=')
    code_challenge_method = "S256"

    # Construct Auth0 authorize URL
    authorize_params = {
        "response_type": "code",
        "client_id": settings.AUTH0_CLIENT_ID,
        "redirect_uri": settings.AUTH0_CALLBACK_URL,
        "scope": "openid profile email offline_access", # Request refresh token
        "realm": "Username-Password-Authentication",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "audience": settings.AUTH0_AUDIENCE, # Request audience for access token
    }
    authorize_url = f"https://{settings.AUTH0_DOMAIN}/authorize?{urlencode(authorize_params)}"

    return RedirectResponse(url=authorize_url)


# --- Callback Endpoint (for redirect flow) ---
@auth_router.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None, error_description: str | None = None):
    """
    Handles the callback from Auth0 after authentication via redirect.
    Exchanges the authorization code for tokens, validates the ID token,
    and stores user information in the session.
    """
    if error:
        print(f"Auth0 Error: {error} - {error_description}")
        # Redirect back to frontend with error query params? Or show error page?
        # Example redirect: return RedirectResponse(url=f"{settings.APP_BASE_URL}/login?error={error}&error_description={error_description}")
        raise HTTPException(status_code=400, detail=f"Auth0 error: {error_description or error}")

    stored_state = request.session.get("state")
    stored_code_verifier = request.session.get("code_verifier")

    if not code or not state or not stored_state or not stored_code_verifier:
        raise HTTPException(status_code=400, detail="Missing code, state, or session data")

    if state != stored_state:
        raise HTTPException(status_code=403, detail="Invalid state parameter (CSRF protection)")

    # Exchange code for tokens
    token_url = f"https://{settings.AUTH0_DOMAIN}/oauth/token"
    token_payload = {
        "grant_type": "authorization_code",
        "client_id": settings.AUTH0_CLIENT_ID,
        "client_secret": settings.AUTH0_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.AUTH0_CALLBACK_URL,
        "code_verifier": stored_code_verifier,
    }

    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(token_url, data=token_payload)
            token_response.raise_for_status() # Raise exception for 4xx/5xx responses
            token_data = token_response.json()
        except httpx.HTTPStatusError as e:
            print(f"Token exchange failed: {e.response.status_code} - {e.response.text}")
            raise HTTPException(status_code=400, detail=f"Failed to exchange code for token: {e.response.text}")
        except Exception as e:
            print(f"Unexpected error during token exchange: {e}")
            raise HTTPException(status_code=500, detail="Internal server error during token exchange")

    id_token = token_data.get("id_token")
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token") # Store securely if needed for backend calls

    if not id_token:
         raise HTTPException(status_code=400, detail="ID token not found in response")

    # Validate the ID token
    try:
        user_profile = await validate_token(id_token)
    except HTTPException as e:
        # Re-raise validation errors
        raise e
    except Exception as e:
        print(f"Unexpected error during token validation: {e}")
        raise HTTPException(status_code=500, detail="Failed to validate token")


    # --- User Persistence (Optional but Recommended) ---
    # ... (add your Prisma upsert logic here if needed) ...
    # ----------------------------------------------------

    # Store user info and tokens in the session
    request.session["user"] = user_profile
    request.session["id_token"] = id_token
    # request.session["access_token"] = access_token
    # request.session["refresh_token"] = refresh_token

    # Clear temporary PKCE/state data
    request.session.pop("state", None)
    request.session.pop("code_verifier", None)

    # Redirect user back to the frontend application
    return RedirectResponse(url=settings.APP_BASE_URL) # Or a specific post-login page


# --- Logout Endpoint ---
@auth_router.get("/logout")
async def logout(request: Request):
    """Clears the local session and redirects the user to Auth0 logout."""
    session_user = request.session.pop("user", None)
    request.session.pop("id_token", None)
    request.session.pop("access_token", None)
    request.session.pop("refresh_token", None)
    request.session.clear() # Ensure session is fully cleared

    # Redirect to Auth0 logout endpoint
    logout_params = {
        "client_id": settings.AUTH0_CLIENT_ID,
        "returnTo": settings.APP_BASE_URL # URL to return to after Auth0 logout
    }
    logout_url = f"https://{settings.AUTH0_DOMAIN}/v2/logout?{urlencode(logout_params)}"

    return RedirectResponse(url=logout_url)


# --- Get User Endpoint (Check Session) ---
@auth_router.get("/me")
async def get_me(user: dict = Depends(get_current_user)): # Use get_current_user to enforce login
    """Simple endpoint to check the current user session. Requires authentication."""
    # No need for the if not user check, as get_current_user handles it
    return user


