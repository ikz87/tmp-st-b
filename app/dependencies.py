from fastapi import Request, HTTPException, status, Depends

async def get_optional_current_user(request: Request) -> dict | None:
    """
    Returns the user dict from the session if available, otherwise None.
    Does not raise an exception if the user is not logged in.
    Used for routes like login/callback where user might or might not be logged in.
    """
    return request.session.get("user", None)


async def get_current_user(user: dict | None = Depends(get_optional_current_user)) -> dict:
    """
    Returns the user dict from the session.
    Raises a 401 Unauthorized exception if the user is not logged in.
    Use this dependency for protected routes.
    """
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}, # Optional, indicates auth type
        )
    return user

