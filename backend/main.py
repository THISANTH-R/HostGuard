import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from .api import router
from .startup import start_all_services

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

background_tasks = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting up HostGuard Backend...")
    tasks = await start_all_services()
    background_tasks.extend(tasks)
    
    yield
    
    # Shutdown
    logger.info("Shutting down HostGuard Backend...")
    for task in background_tasks:
        task.cancel()
        
    await asyncio.gather(*background_tasks, return_exceptions=True)
    logger.info("Shutdown complete.")

app = FastAPI(title="HostGuard API", lifespan=lifespan)

# Allow all origins for local dashboard dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
