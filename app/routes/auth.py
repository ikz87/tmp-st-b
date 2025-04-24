import httpx
import secrets
import hashlib
import base64
from urllib.parse import urlencode
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from jose import jwt, JWTError
from jose.utils import base64url_decode
from app.config import settings
from app.dependencies import get_optional_current_user # Use optional for login/callback

auth_router = APIRouter()

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


@auth_router.get("/login")
async def login(request: Request, user: dict | None = Depends(get_optional_current_user)):
    """
    Initiates the Auth0 login flow by redirecting the user to Auth0.
    Generates state and PKCE parameters.
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
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "audience": settings.AUTH0_AUDIENCE, # Request audience for access token
    }
    authorize_url = f"https://{settings.AUTH0_DOMAIN}/authorize?{urlencode(authorize_params)}"

    return RedirectResponse(url=authorize_url)


@auth_router.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None, error_description: str | None = None):
    """
    Handles the callback from Auth0 after authentication.
    Exchanges the authorization code for tokens, validates the ID token,
    and stores user information in the session.
    """
    if error:
        print(f"Auth0 Error: {error} - {error_description}")
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
    # Here you would typically use Prisma (or your ORM) to find or create the user
    # based on user_profile['sub'] (Auth0 User ID) or user_profile['email']
    # Example (requires Prisma setup):
    # from app.prisma import db
    # user = await db.user.upsert(
    #     where={'email': user_profile.get('email')},
    #     data={
    #         'create': {
    #             'email': user_profile.get('email'),
    #             'name': user_profile.get('name', 'Unknown'),
    #             'auth0_sub': user_profile.get('sub'), # Add auth0_sub field to schema
    #             # Avoid storing passwords for Auth0 users
    #         },
    #         'update': {
    #             'name': user_profile.get('name', 'Unknown'),
    #             'auth0_sub': user_profile.get('sub'),
    #         }
    #     }
    # )
    # ----------------------------------------------------

    # Store user info and tokens in the session
    # Be mindful of cookie size limits. Store only what's necessary.
    # Avoid storing access/refresh tokens in the session cookie if possible,
    # unless the frontend *truly* needs them (less common in BFF).
    # If the backend needs to make API calls, manage tokens server-side.
    request.session["user"] = user_profile
    request.session["id_token"] = id_token # Useful for user info display
    # request.session["access_token"] = access_token # Store only if needed by frontend/backend calls initiated via frontend state
    # request.session["refresh_token"] = refresh_token # Store securely (e.g., encrypted) if backend needs long-term access

    # Clear temporary PKCE/state data
    request.session.pop("state", None)
    request.session.pop("code_verifier", None)

    # Redirect user back to the frontend application
    return RedirectResponse(url=settings.APP_BASE_URL) # Or a specific post-login page


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
    # Starting from Auth0 SDK v2.0, use /v2/logout
    # Check Auth0 documentation for the most current endpoint structure if needed.
    logout_url = f"https://{settings.AUTH0_DOMAIN}/v2/logout?{urlencode(logout_params)}"

    return RedirectResponse(url=logout_url)


@auth_router.get("/me")
async def get_me(user: dict = Depends(get_optional_current_user)):
    """Simple endpoint to check the current user session."""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

