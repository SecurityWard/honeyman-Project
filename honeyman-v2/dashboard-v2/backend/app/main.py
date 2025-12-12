"""
Honeyman V2 Dashboard Backend - FastAPI Application
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import time
import logging
import asyncio

from .core.config import settings
from .api import sensors, threats, analytics, auth, onboarding, websocket as ws_router
from .mqtt.subscriber import mqtt_subscriber
from .services.redis_client import redis_client
from .services.websocket import manager

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    openapi_url=f"{settings.API_PREFIX}/openapi.json"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gzip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add X-Process-Time header to all responses"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": f"{settings.API_PREFIX}/docs"
    }


# Include API routers
app.include_router(auth.router, prefix=settings.API_PREFIX, tags=["auth"])
app.include_router(sensors.router, prefix=settings.API_PREFIX, tags=["sensors"])
app.include_router(threats.router, prefix=settings.API_PREFIX, tags=["threats"])
app.include_router(analytics.router, prefix=settings.API_PREFIX, tags=["analytics"])
app.include_router(onboarding.router, prefix=settings.API_PREFIX, tags=["onboarding"])
app.include_router(ws_router.router, prefix=settings.API_PREFIX, tags=["websocket"])


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"API documentation: {settings.API_PREFIX}/docs")

    # Connect to Redis
    try:
        await redis_client.connect()
        logger.info("Redis connected")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")

    # Start MQTT subscriber
    try:
        mqtt_subscriber.start()
        await mqtt_subscriber.start_worker()
        logger.info("MQTT subscriber started")
    except Exception as e:
        logger.error(f"Failed to start MQTT subscriber: {e}")

    # Start WebSocket Redis subscriber
    try:
        manager.subscriber_task = asyncio.create_task(manager.start_redis_subscriber())
        logger.info("WebSocket Redis subscriber started")
    except Exception as e:
        logger.error(f"Failed to start WebSocket subscriber: {e}")

    logger.info(f"{settings.APP_NAME} started successfully")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down Honeyman Dashboard Backend")

    # Stop MQTT subscriber
    try:
        mqtt_subscriber.stop()
        logger.info("MQTT subscriber stopped")
    except Exception as e:
        logger.error(f"Error stopping MQTT subscriber: {e}")

    # Stop WebSocket subscriber
    try:
        manager.stop_redis_subscriber()
        logger.info("WebSocket subscriber stopped")
    except Exception as e:
        logger.error(f"Error stopping WebSocket subscriber: {e}")

    # Disconnect from Redis
    try:
        await redis_client.disconnect()
        logger.info("Redis disconnected")
    except Exception as e:
        logger.error(f"Error disconnecting from Redis: {e}")

    logger.info("Shutdown complete")
