"""Platform Identity Faucet - FastAPI Application."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.routers import faucet
from app.services.core_client import dash_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    import asyncio
    # Startup: ensure wallet exists with retries
    max_retries = 30
    last_error = None
    for attempt in range(max_retries):
        try:
            dash_client.ensure_wallet()
            print("Faucet wallet ready")
            break
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                print(f"Waiting for dashcore... ({attempt + 1}/{max_retries})")
                await asyncio.sleep(2)
    else:
        raise RuntimeError(f"Could not initialize wallet after {max_retries} attempts: {last_error}")
    yield
    # Shutdown: nothing to clean up


app = FastAPI(
    title="Platform Identity Faucet",
    description="Get testnet Dash identity credentials with one click",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(faucet.router)

# Mount static files
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
async def root():
    """Serve the frontend."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Platform Identity Faucet API", "docs": "/docs"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}
