import uvicorn

from fastapi import FastAPI
from settings import settings
from routers import router
from db import create_tables
from fastapi.middleware.cors import CORSMiddleware

create_tables()
app = FastAPI(debug=settings.SERVER_TEST)
app.include_router(router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.SERVER_ADDR,
        port=settings.SERVER_PORT,
        reload=settings.SERVER_TEST,
        log_level="debug" if settings.SERVER_TEST else "info",
    )
