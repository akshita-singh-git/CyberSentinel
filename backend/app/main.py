from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.database import Base, engine
from app.api.routes import router

Base.metadata.create_all(bind=engine)
app = FastAPI(title=settings.app_name, description="Local-first security monitoring and incident response demo API", version="1.0.0")
origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)

@app.get("/")
def root():
    return {"application":"CyberSentinel","status":"operational","docs":"/docs"}

@app.get("/api/v1/health")
def health():
    return {"status":"healthy","application":"CyberSentinel","version":"1.0.0"}
