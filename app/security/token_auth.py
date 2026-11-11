import hmac
import os

from fastapi import Header, HTTPException


async def verify_token(x_service_token: str = Header(...)) -> None:
    expected = os.environ.get("INTERNAL_SERVICE_TOKEN", "")
    # compare_digest: the time taken does not reveal how much of the token was right.
    if not expected or not hmac.compare_digest(x_service_token.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid service token")
