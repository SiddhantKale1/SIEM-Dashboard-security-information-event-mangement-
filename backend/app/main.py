import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.database.connection import Database
from app.config.settings import settings
from app.api import auth, enrollment, agent

# Setup logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiter — keyed by client IP
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="SIEM MVP API", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

from app.api.auth import router as auth_router
from app.api.enrollment import router as enrollment_router
from app.api.agent import router as agent_router
from app.api.network import router as network_router
from app.api.devices import router as devices_router
from app.api.logs import router as logs_router
from app.api.anomalies import router as anomalies_router

app.include_router(auth_router)
app.include_router(enrollment_router)
app.include_router(agent_router)
app.include_router(network_router)
app.include_router(devices_router)
app.include_router(logs_router)
app.include_router(anomalies_router)

# CORS middleware — support localhost, 127.0.0.1, and all local private network IPs
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info("Starting up SIEM API server...")
    await Database.connect_db()

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down SIEM API server...")
    await Database.close_db()

@app.get("/")
async def root():
    return {"message": "SIEM MVP API is running"}

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
