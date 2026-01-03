"""
Chatbot API Routes
Endpoints for the WebShield AI assistant chatbot
"""

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from .chatbot_assistant import get_chatbot

logger = logging.getLogger(__name__)

chatbot_router = APIRouter(prefix="/api/chatbot", tags=["chatbot"])


class ChatMessage(BaseModel):
    """Chat message request model"""

    message: str = Field(..., min_length=1, max_length=500, description="User's message")
    context: Optional[Dict] = Field(None, description="Optional context (scan results, etc.)")


class ChatResponse(BaseModel):
    """Chat response model"""

    response: str
    timestamp: str
    suggestions: Optional[List[str]] = None


@chatbot_router.post("/chat", response_model=ChatResponse)
async def chat(request: Request, chat_message: ChatMessage):
    """
    Send message to chatbot and get response

    Args:
        chat_message: User's message and optional context

    Returns:
        Chatbot response with suggestions
    """
    try:
        logger.info(f"📨 Received chat message: {chat_message.message}")
        chatbot = get_chatbot()

        # Get response from chatbot
        response = chatbot.get_response(user_message=chat_message.message, context=chat_message.context)

        logger.info(f"🤖 Chatbot response: {response[:100] if response else 'None'}...")

        # Ensure response is not None
        if not response:
            response = "I apologize, but I couldn't generate a response. Please try rephrasing your question."

        # Get conversation starters for first message
        suggestions = None
        if "hello" in chat_message.message.lower() or "hi" in chat_message.message.lower():
            suggestions = chatbot.get_conversation_starters()[:4]

        from datetime import datetime

        return ChatResponse(response=response, timestamp=datetime.utcnow().isoformat(), suggestions=suggestions)

    except Exception as e:
        logger.error(f"💥 Chatbot error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to process chat message: {str(e)}")


@chatbot_router.post("/explain-scan")
async def explain_scan(request: Request, scan_data: Dict):
    """
    Get explanation for scan results

    Args:
        scan_data: Scan result data

    Returns:
        Human-friendly explanation
    """
    try:
        chatbot = get_chatbot()
        explanation = chatbot.explain_scan_result(scan_data)

        from datetime import datetime

        return {"explanation": explanation, "timestamp": datetime.utcnow().isoformat()}

    except Exception as e:
        logger.error(f"Scan explanation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate explanation. Please try again.")


@chatbot_router.get("/suggestions")
async def get_suggestions():
    """
    Get conversation starter suggestions

    Returns:
        List of suggested questions
    """
    try:
        chatbot = get_chatbot()
        suggestions = chatbot.get_conversation_starters()

        return {"suggestions": suggestions}

    except Exception as e:
        logger.error(f"Suggestions error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get suggestions.")


@chatbot_router.get("/health")
async def chatbot_health():
    """
    Check chatbot service health

    Returns:
        Health status
    """
    try:
        chatbot = get_chatbot()

        return {
            "status": "healthy",
            "ai_enabled": chatbot.use_ai,
            "mode": "AI-powered" if chatbot.use_ai else "Rule-based",
        }

    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {"status": "degraded", "error": str(e)}
