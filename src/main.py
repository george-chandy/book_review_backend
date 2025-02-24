from fastapi import FastAPI
from src.auth.router import router as auth_router

app = FastAPI()


@app.get("/", response_model=str)
async def status() -> str:
    return "Bookreview server is running"


# Include all routers here
app.include_router(auth_router)
