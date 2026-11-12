from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "CyberSentinel API"
    database_url: str = "sqlite:///./cybersentinel.db"
    secret_key: str = "development-only-change-me"
    access_token_minutes: int = 720
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
