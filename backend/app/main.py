import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.connection import Database
from app.config.settings import settings
from app.api import auth, enrollment, agent

# Setup logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="SIEM MVP API", version="1.0.0")

from app.api.auth import router as auth_router
from app.api.enrollment import router as enrollment_router
from app.api.agent import router as agent_router
from app.api.network import router as network_router
from app.api.devices import router as devices_router
from app.api.logs import router as logs_router

app.include_router(auth_router)
app.include_router(enrollment_router)
app.include_router(agent_router)
app.include_router(network_router)
app.include_router(devices_router)
app.include_router(logs_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
