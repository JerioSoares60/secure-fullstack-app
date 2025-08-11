from pydantic import BaseModel, validator, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import base64

class HandshakeRequest(BaseModel):
    client_public_key: str = Field(
        ...,
        description="Base64 encoded client ECC public key in PEM format",
        min_length=100,
        example="-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
    )

    @validator('client_public_key')
    def validate_public_key(cls, v):
        if not v.startswith("-----BEGIN PUBLIC KEY-----"):
            raise ValueError("Invalid public key format. Must be PEM encoded.")
        return v.strip()

class HandshakeResponse(BaseModel):
    session_id: str = Field(
        ...,
        description="UUID v4 session identifier",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    server_public_key: str = Field(
        ...,
        description="Base64 encoded server ECC public key in PEM format",
        example="-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
    )
    expires_at: str = Field(
        ...,
        description="ISO 8601 timestamp when session expires",
        example="2023-12-31T23:59:59.999Z"
    )

class EncryptedPayload(BaseModel):
    payload: str = Field(
        ...,
        description="Base64 encoded encrypted data",
        min_length=16,
        example="aGVsbG8gd29ybGQh"
    )
    iv: str = Field(
        ...,
        description="Base64 encoded initialization vector (12 bytes for AES-GCM)",
        min_length=16,
        example="YWJjZGVmZ2hpamts"
    )
    tag: str = Field(
        ...,
        description="Base64 encoded authentication tag (16 bytes for AES-GCM)",
        min_length=24,
        example="bW5vcHFyc3R1dnd4eXo="
    )
    signature: str = Field(
        ...,
        description="Base64 encoded HMAC-SHA256 signature",
        min_length=44,
        example="aGVsbG8gd29ybGQhIHNpZ25hdHVyZQ=="
    )

    @validator('payload', 'iv', 'tag', 'signature')
    def validate_base64(cls, v):
        try:
            base64.b64decode(v, validate=True)
        except ValueError:
            raise ValueError('Invalid base64 encoding')
        return v

    @validator('iv')
    def validate_iv_length(cls, v):
        if len(base64.b64decode(v)) != 12:
            raise ValueError('IV must be exactly 12 bytes')
        return v

    @validator('tag')
    def validate_tag_length(cls, v):
        if len(base64.b64decode(v)) != 16:
            raise ValueError('Tag must be exactly 16 bytes')
        return v

class SecureRequest(BaseModel):
    session_id: str = Field(
        ...,
        description="UUID v4 session identifier",
        example="550e8400-e29b-41d4-a716-446655440000"
    )
    encrypted_data: EncryptedPayload

class SecureResponse(BaseModel):
    encrypted_data: EncryptedPayload
    message: str = Field(
        ...,
        description="Human-readable status message",
        example="Data processed successfully"
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp of response",
        example="2023-01-01T00:00:00.000Z"
    )

class UserData(BaseModel):
    user_id: str = Field(
        ...,
        description="Unique user identifier",
        example="usr_12345"
    )
    username: str = Field(
        ...,
        description="Unique username",
        min_length=3,
        max_length=50,
        example="secure_user"
    )
    email: str = Field(
        ...,
        description="Valid email address",
        pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
        example="user@example.com"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional user attributes"
    )

class MessageData(BaseModel):
    message_id: str = Field(
        ...,
        description="Unique message identifier",
        example="msg_67890"
    )
    content: str = Field(
        ...,
        description="Message content",
        min_length=1,
        max_length=1000,
        example="Hello, world!"
    )
    sender: str = Field(
        ...,
        description="Sender identifier",
        example="user_123"
    )
    recipients: List[str] = Field(
        ...,
        description="List of recipient identifiers",
        min_items=1,
        example=["user_456", "user_789"]
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp of message creation",
        example="2023-01-01T00:00:00.000Z"
    )

class ErrorResponse(BaseModel):
    error: str = Field(
        ...,
        description="Human-readable error message",
        example="Invalid session ID"
    )
    code: str = Field(
        ...,
        description="Machine-readable error code",
        example="invalid_session"
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp of error",
        example="2023-01-01T00:00:00.000Z"
    )
    details: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional error context"
    )
    stack_trace: Optional[str] = Field(
        None,
        description="Debug stack trace (development only)"
    )

class SessionInfo(BaseModel):
    session_id: str
    client_id: Optional[str] = Field(
        None,
        description="Client identifier if available"
    )
    created_at: str = Field(
        ...,
        description="ISO 8601 timestamp of session creation"
    )
    expires_at: str = Field(
        ...,
        description="ISO 8601 timestamp of session expiration"
    )
    is_active: bool = Field(
        ...,
        description="Whether session is currently active"
    )
    last_accessed: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp of last access"
    )

class HealthCheck(BaseModel):
    status: str = Field(
        ...,
        description="Service health status",
        example="healthy",
        pattern="^(healthy|degraded|unhealthy)$"
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp of check"
    )
    version: str = Field(
        ...,
        description="Service version",
        example="1.0.0"
    )
    dependencies: Dict[str, str] = Field(
        ...,
        description="Status of service dependencies"
    )
    uptime: float = Field(
        ...,
        description="Service uptime in seconds"
    )
