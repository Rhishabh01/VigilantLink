"""
Domain Age Router: Endpoint for checking domain registration age.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..services.domain_age import get_domain_age_info

router = APIRouter()

class DomainAgeRequest(BaseModel):
    url: str

@router.post("/domain-age")
async def get_domain_age(body: DomainAgeRequest) -> dict:
    if not body.url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        result = await get_domain_age_info(body.url)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch domain age: {str(e)}")
