import os

from fastapi import Header, HTTPException


async def verify_token(x_service_token: str = Header(...)) -> None:
    expected = os.environ.get("INTERNAL_SERVICE_TOKEN", "")
    if not expected or x_service_token != expected:
        raise HTTPException(status_code=401, detail="Invalid service token")
