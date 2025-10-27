"""
Main FastAPI application entry point
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog
from contextlib import asynccontextmanager

from app.api import (
    alerts, threats, auth, dashboard, models as models_api,
    nlp, explainability, graph, predictive, siem
)
from app.core.config import settings
from app.core.database import init_db

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    logger.info("Starting CloudSentinelAI...")
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down CloudSentinelAI...")


app = FastAPI(
    title="CloudSentinelAI",
    description="AI-Powered Cloud Threat Detection System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error("Global exception", exc_info=exc, path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "CloudSentinelAI",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


# Include API routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["Threats"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(models_api.router, prefix="/api/v1/models", tags=["ML Models"])
app.include_router(nlp.router, prefix="/api/v1/nlp", tags=["Natural Language"])
app.include_router(explainability.router, prefix="/api/v1/explainability", tags=["Explainability"])
app.include_router(graph.router, prefix="/api/v1/graph", tags=["Graph Analysis"])
app.include_router(predictive.router, prefix="/api/v1/predictive", tags=["Predictive"])
app.include_router(siem.router, prefix="/api/v1/siem", tags=["SIEM Integration"])
