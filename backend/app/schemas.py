from datetime import datetime
from pydantic import BaseModel, Field

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str
    password: str = Field(min_length=8, max_length=128)

class LoginIn(BaseModel):
    email: str
    password: str

class EventIn(BaseModel):
    event_type: str = "authentication"
    source: str = "manual"
    source_ip: str = "127.0.0.1"
    username: str = "unknown"
    hostname: str = "endpoint"
    message: str = Field(min_length=3, max_length=4000)
    failed_count: int = Field(default=0, ge=0, le=100000)
    unusual_hour: int = Field(default=0, ge=0, le=1)
    privileged: int = Field(default=0, ge=0, le=1)
    process_name: str = ""

class IncidentUpdate(BaseModel):
    status: str = Field(pattern="^(open|investigating|contained|resolved)$")

class NoteIn(BaseModel):
    note: str = Field(min_length=2, max_length=3000)
