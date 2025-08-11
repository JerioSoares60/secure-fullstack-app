from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from uvicorn import run
from dotenv import load_dotenv
import os
from datetime import datetime
import logging
from app.routes import router
from app.encryptor import initialize_encryption_system
from app.schemas import ErrorResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Environment configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
SSL_ENABLED = os.getenv("SSL_ENABLED", "false").lower() == "true"

# Initialize FastAPI app
app = FastAPI(
    title="Secure Fullstack App API",
    description="E2EE API with AES-256-GCM and ECC",
    version="1.0.0",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if ENVIRONMENT == "development" else None
)

# Add middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if ENVIRONMENT == "development" else [
        "localhost",
        "127.0.0.1",
        os.getenv("TRUSTED_HOST", "")
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ENVIRONMENT == "development" else [
        "http://localhost:3000",
        "https://localhost:3000",
        os.getenv("ALLOWED_ORIGIN", "")
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Session-ID"]
)

# Include router
app.include_router(router, prefix="/api/v1")

# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    logger.error(f"HTTPException: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            code=str(exc.status_code),
            timestamp=datetime.utcnow().isoformat()
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            code="500",
            timestamp=datetime.utcnow().isoformat(),
            details={
                "type": type(exc).__name__,
                "message": str(exc)
            }
        ).dict()
    )

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    try:
        initialize_encryption_system()
        logger.info("🔐 Encryption system initialized")
    except Exception as e:
        logger.critical(f"Failed to initialize encryption system: {str(e)}")
        raise

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 Application shutting down")

# Health check endpoint
@app.get("/health", tags=["Monitoring"])
async def health_check():
    """Service health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "environment": ENVIRONMENT
    }

# Run the application
if __name__ == "__main__":
    ssl_params = {}
    if SSL_ENABLED:
        ssl_keyfile = os.getenv("SSL_KEYFILE")
        ssl_certfile = os.getenv("SSL_CERTFILE")
        
        if not ssl_keyfile or not ssl_certfile:
            logger.error("SSL enabled but keyfile or certfile not specified")
            raise ValueError("SSL configuration incomplete")
            
        ssl_params = {
            "ssl_keyfile": ssl_keyfile,
            "ssl_certfile": ssl_certfile
        }

    run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=ENVIRONMENT == "development",
        log_level="info",
        **ssl_params
    )