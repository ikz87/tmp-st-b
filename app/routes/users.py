# FILE: app/routes/users.py

import httpx
import time
from typing import Dict, Any
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Body,
    Request,
    status,
)

from app.dependencies import get_current_user # To ensure user is logged in
from app.config import settings # To get Auth0 settings

# Create a router for user-related endpoints
users_router = APIRouter()

# --- Helper Function to get Management API Token (Cache this!) ---
# WARNING: Simple in-memory cache. Use Redis/Memcached for production scalability.
management_api_token_cache = {"token": None, "expires_at": 0}

async def get_management_api_token() -> str:
    """
    Retrieves a cached or new Auth0 Management API token using Client Credentials.
    """
    global management_api_token_cache
    now = time.time()

    # Check cache first
    if management_api_token_cache["token"] and management_api_token_cache["expires_at"] > now:
        print("DEBUG: Using cached Management API token.") # Optional debug log
        return management_api_token_cache["token"]

    # Get new token if cache is invalid/expired
    print("DEBUG: Fetching new Management API token.") # Optional debug log
    token_url = f"https://{settings.AUTH0_DOMAIN}/oauth/token"
    # Ensure the audience is correct for the Management API
    mgmt_api_audience = f"https://{settings.AUTH0_DOMAIN}/api/v2/"
    if settings.AUTH0_AUDIENCE != mgmt_api_audience:
         print(f"WARNING: AUTH0_AUDIENCE in .env ({settings.AUTH0_AUDIENCE}) might not be the Management API audience ({mgmt_api_audience}). Using Management API audience for token request.")

    payload = {
        'grant_type': 'client_credentials',
        'client_id': settings.AUTH0_CLIENT_ID,
        'client_secret': settings.AUTH0_CLIENT_SECRET,
        'audience': mgmt_api_audience # Explicitly use Management API audience
    }
    headers = {'content-type': 'application/json'}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(token_url, json=payload, headers=headers)
            response.raise_for_status()
            token_data = response.json()
            access_token = token_data['access_token']
            # Use expires_in, default to 1 hour (3600s), subtract 60s buffer
            expires_in = token_data.get('expires_in', 3600)
            expires_at = now + expires_in - 60

            # Update cache
            management_api_token_cache["token"] = access_token
            management_api_token_cache["expires_at"] = expires_at
            print(f"DEBUG: New Management API token obtained. Expires around: {time.ctime(expires_at)}") # Optional debug log

            return access_token
        except httpx.RequestError as e:
            print(f"Network error getting Management API token: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not connect to Auth0 to obtain Management API token."
            )
        except httpx.HTTPStatusError as e:
            print(f"Error getting Management API token: {e.response.status_code} - {e.response.text}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not obtain Management API token due to Auth0 error."
            )
        except Exception as e:
            print(f"Unexpected error getting Management API token: {type(e).__name__} - {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal error obtaining Management API token."
            )
# --- End Helper Function ---


# --- Define the PATCH endpoint ---
@users_router.patch(
    "/me/metadata",
    status_code=status.HTTP_200_OK,
    summary="Update logged-in user's metadata",
    response_description="User metadata updated successfully",
)
async def update_user_metadata(
    request: Request, # Needed to access the session for potential updates
    metadata_update: Dict[str, Any] = Body(
        ...,
        example={"firstName": "Jane", "lastName": "Doe", "path": "/some/path"}
    ), # Get new metadata from request body
    user: dict = Depends(get_current_user) # Ensures user is logged in, gets current user profile from session
):
    """
    Updates the `user_metadata` for the currently authenticated user in Auth0.

    Receives a JSON body containing the key-value pairs to update within `user_metadata`.
    """
    auth0_user_id = user.get("sub") # Get Auth0 user ID (subject) from session profile
    if not auth0_user_id:
         # This should ideally not happen if get_current_user works correctly
         raise HTTPException(
             status_code=status.HTTP_400_BAD_REQUEST,
             detail="User ID ('sub') not found in session."
         )

    print(f"DEBUG: Attempting to update metadata for user: {auth0_user_id}") # Optional debug log

    # 1. Get Management API Token
    try:
        mgmt_token = await get_management_api_token()
    except HTTPException as e:
        # Re-raise errors from token fetching, potentially with more context
        raise HTTPException(status_code=e.status_code, detail=f"Failed to get management token: {e.detail}")

    # 2. Prepare Auth0 Management API Request
    update_url = f"https://{settings.AUTH0_DOMAIN}/api/v2/users/{auth0_user_id}"
    headers = {
        'Authorization': f'Bearer {mgmt_token}',
        'Content-Type': 'application/json'
    }
    # IMPORTANT: Send *only* the user_metadata field containing the updates.
    # This performs a PATCH operation on the user_metadata object in Auth0.
    payload = {
        "user_metadata": metadata_update
    }
    print(f"DEBUG: Sending PATCH to Auth0: URL={update_url}, Payload={payload}") # Optional debug log

    # 3. Call Auth0 Management API
    async with httpx.AsyncClient() as client:
        try:
            response = await client.patch(update_url, json=payload, headers=headers)
            response.raise_for_status() # Check for 4xx/5xx errors from Auth0 API
            updated_user_data = response.json()
            print(f"DEBUG: Auth0 API update successful. Response status: {response.status_code}") # Optional debug log

            # --- 4. Optional but Recommended: Update the Backend Session ---
            # This ensures subsequent calls to /auth/me reflect the change immediately
            # without needing a full re-login.
            try:
                current_session_user = request.session.get("user", {})
                # Ensure user_metadata exists in the session profile
                if "user_metadata" not in current_session_user or not isinstance(current_session_user.get("user_metadata"), dict):
                    current_session_user["user_metadata"] = {}

                # Merge the updates into the session's user_metadata
                current_session_user["user_metadata"].update(metadata_update)

                # Save the modified profile back to the session
                request.session["user"] = current_session_user
                print("DEBUG: Backend session updated with new metadata.") # Optional debug log
            except Exception as session_error:
                # Log the error but don't fail the request just because session update failed
                print(f"WARNING: Failed to update backend session after metadata change: {session_error}")
            # --- End Session Update ---

            # 5. Return Success Response
            # You might return the updated metadata or just a success message
            return {
                "message": "Metadata updated successfully",
                "updated_metadata": updated_user_data.get("user_metadata", {}) # Return the metadata as confirmed by Auth0
            }

        except httpx.RequestError as e:
             print(f"Network error updating metadata via Management API: {e}")
             raise HTTPException(
                 status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                 detail="Could not connect to Auth0 to update metadata."
             )
        except httpx.HTTPStatusError as e:
            print(f"Error updating metadata via Management API: {e.response.status_code} - {e.response.text}")
            # Provide a more specific error if possible, otherwise generic
            detail = "Failed to update user metadata via Auth0 API."
            if e.response.status_code == 400:
                detail = "Bad request updating metadata (check payload/permissions)."
            elif e.response.status_code == 401:
                 detail = "Unauthorized to update metadata (check Management API token/permissions)."
            elif e.response.status_code == 403:
                 detail = "Forbidden to update metadata (check Management API permissions)."
            elif e.response.status_code == 404:
                 detail = "User not found in Auth0."

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, # Or map specific Auth0 errors if needed
                detail=detail
            )
        except Exception as e:
            print(f"Unexpected error updating metadata: {type(e).__name__} - {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred while updating metadata."
            )


