"""
Natural Language Processing endpoints
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any

from app.core.database import get_db
from app.core.security import get_current_user
from app.services.nlp_query import NaturalLanguageQueryService, QuerySuggestionService

router = APIRouter()
nlp_service = NaturalLanguageQueryService()
suggestion_service = QuerySuggestionService()


@router.get("/query")
async def natural_language_query(
    q: str = Query(..., description="Natural language query", min_length=3),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Query threats using natural language
    
    Example queries:
    - "Show critical threats from last 24 hours"
    - "Find suspicious logins from Russia"
    - "List all open alerts with high severity"
    """
    result = await nlp_service.process_query(q, db)
    return result


@router.get("/examples")
async def get_query_examples(
    current_user: dict = Depends(get_current_user)
):
    """
    Get example natural language queries
    """
    return {
        "examples": suggestion_service.get_example_queries()
    }


@router.get("/help")
async def get_query_help(
    current_user: dict = Depends(get_current_user)
):
    """
    Get help for natural language queries
    """
    return suggestion_service.get_query_help()
