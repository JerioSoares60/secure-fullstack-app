from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from app.schemas import (
    HandshakeRequest, HandshakeResponse, EncryptedPayload, 
    SecureRequest, SecureResponse, UserData, MessageData, 
    ErrorResponse, SessionInfo, HealthCheck
)
from app.encryptor import (
    get_server_public_key,
    encrypt_data, decrypt_data_with_session,
    encrypt_data_legacy, decrypt_data_legacy
)
import logging
from datetime import datetime
import time
import traceback
import uuid
from datetime import timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

# Example session store
sessions = {}

def create_session(client_id, client_public_key):
    session_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=1)
    sessions[session_id] = {
        "client_id": client_id,
        "client_public_key": client_public_key,
        "created_at": datetime.utcnow(),
        "expires_at": expires_at,
        # ...other fields...
    }
    return session_id, expires_at

def get_session(session_id):
    return sessions.get(session_id)

def cleanup_expired_sessions():
    now = datetime.utcnow()
    expired = [sid for sid, s in sessions.items() if s["expires_at"] < now]
    for sid in expired:
        del sessions[sid]
    logger.info(f"Cleaned up {len(expired)} expired sessions.")

def get_current_session(request: Request):
    session_id = request.headers.get("X-Session-ID")
    logger.info(f"get_current_session: received session_id={session_id}")
    if not session_id:
        logger.error("Session ID not provided in headers")
        raise HTTPException(status_code=401, detail="Session ID required")
    session = get_session(session_id)
    logger.info(f"get_current_session: get_session({session_id}) returned: {session} (type: {type(session)})")
    if not session or not isinstance(session, dict):
        logger.error(f"Session not found or invalid type: {session}")
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    # Defensive: ensure returned dict always has both keys, but do NOT inject session_id into session dict
    # Instead, only return session_id in the wrapper dict
    return {"session": session, "session_id": session_id}

@router.post("/handshake", response_model=HandshakeResponse)
async def perform_handshake(request: HandshakeRequest):
    """Perform ECC key exchange and establish session"""
    try:
        logger.info(f"Handshake request received with client public key length: {len(request.client_public_key)}")
        
        # Create new session (generate a client ID)
        client_id = f"client_{int(time.time())}"
        session_id, expires_at = create_session(client_id, request.client_public_key)
        
        # Get server public key
        server_public_key = get_server_public_key()
        
        logger.info(f"Handshake completed for session: {session_id}")
        
        return HandshakeResponse(
            session_id=session_id,
            server_public_key=server_public_key,
            message="Handshake successful"
        )
    except Exception as e:
        logger.error(f"Handshake failed: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Handshake failed: {str(e)}")

@router.post("/secure/data", response_model=SecureResponse)
async def secure_data_endpoint(request: Request):
    data = await request.json()
    session_id = data.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing session_id")
    encrypted_data = {
        "payload": data.get("payload"),
        "iv": data.get("iv"),
        "tag": data.get("tag"),
        "signature": data.get("signature")
    }
    # Defensive: ensure all fields are present
    for field in ["payload", "iv", "tag", "signature"]:
        if not encrypted_data[field]:
            raise HTTPException(status_code=400, detail=f"Missing field: {field}")
    try:
        decrypted_data = decrypt_data_with_session(encrypted_data, session_id)
        processed_data = {
            "received": decrypted_data,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "processed"
        }
        encrypted_response = encrypt_data(processed_data, session_id)
        return SecureResponse(
            encrypted_data=encrypted_response,
            message="Data processed securely"
        )
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return JSONResponse(status_code=500, content={"error": str(e), "traceback": tb})

@router.post("/secure/user", response_model=SecureResponse)
async def secure_user_endpoint(request: Request):
    data = await request.json()
    session_id = data.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing session_id")
    encrypted_data = {
        "payload": data.get("payload"),
        "iv": data.get("iv"),
        "tag": data.get("tag"),
        "signature": data.get("signature")
    }
    for field in ["payload", "iv", "tag", "signature"]:
        if not encrypted_data[field]:
            raise HTTPException(status_code=400, detail=f"Missing field: {field}")
    try:
        decrypted_data = decrypt_data_with_session(encrypted_data, session_id)
        user_data = UserData(**decrypted_data)
        processed_data = {
            "user_id": user_data.user_id,
            "username": user_data.username,
            "email": user_data.email,
            "status": "validated",
            "timestamp": datetime.utcnow().isoformat()
        }
        encrypted_response = encrypt_data(processed_data, session_id)
        return SecureResponse(
            encrypted_data=encrypted_response,
            message="User data processed securely"
        )
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return JSONResponse(status_code=500, content={"error": str(e), "traceback": tb})

@router.post("/secure/message", response_model=SecureResponse)
async def secure_message_endpoint(request: Request):
    data = await request.json()
    session_id = data.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="Missing session_id")
    encrypted_data = {
        "payload": data.get("payload"),
        "iv": data.get("iv"),
        "tag": data.get("tag"),
        "signature": data.get("signature")
    }
    for field in ["payload", "iv", "tag", "signature"]:
        if not encrypted_data[field]:
            raise HTTPException(status_code=400, detail=f"Missing field: {field}")
    try:
        decrypted_data = decrypt_data_with_session(encrypted_data, session_id)
        message_data = MessageData(**decrypted_data)
        processed_data = {
            "message_id": message_data.message_id,
            "content": message_data.content,
            "sender": message_data.sender,
            "status": "delivered",
            "timestamp": datetime.utcnow().isoformat()
        }
        encrypted_response = encrypt_data(processed_data, session_id)
        return SecureResponse(
            encrypted_data=encrypted_response,
            message="Message processed securely"
        )
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return JSONResponse(status_code=500, content={"error": str(e), "traceback": tb})

@router.get("/session/{session_id}", response_model=SessionInfo)
async def get_session_info(session_id: str):
    """Get session information"""
    try:
        session = get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return SessionInfo(
            session_id=session_id,
            created_at=session["created_at"].isoformat() if hasattr(session["created_at"], 'isoformat') else str(session["created_at"]),
            expires_at=session["expires_at"].isoformat() if hasattr(session["expires_at"], 'isoformat') else str(session["expires_at"]),
            is_active=True
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session info retrieval failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve session info")

@router.delete("/session/{session_id}")
async def invalidate_session(session_id: str):
    """Invalidate a session"""
    try:
        session = get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Remove session (in production, you'd mark it as invalid)
        cleanup_expired_sessions()
        
        logger.info(f"Session invalidated: {session_id}")
        
        return {"message": "Session invalidated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Session invalidation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to invalidate session")

@router.get("/health", response_model=HealthCheck)
async def health_check():
    """Health check endpoint"""
    logger.info("Health check endpoint called")
    return HealthCheck(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        version="1.0.0"
    )

# Legacy endpoint for backward compatibility
@router.post("/legacy/secure-endpoint")
async def legacy_secure_endpoint(request: dict):
    """Legacy secure endpoint using old encryption method"""
    try:
        # Decrypt using legacy method
        decrypted_data = decrypt_data_legacy(request.get("encrypted_data", ""))
        
        # Process data
        processed_data = {
            "received": decrypted_data,
            "status": "processed",
            "method": "legacy"
        }
        
        # Encrypt response using legacy method
        encrypted_response = encrypt_data_legacy(processed_data)
        
        return {
            "encrypted_data": encrypted_response,
            "message": "Legacy data processed"
        }
    except Exception as e:
        logger.error(f"Legacy endpoint failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Legacy processing failed")