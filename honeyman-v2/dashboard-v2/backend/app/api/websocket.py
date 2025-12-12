"""
WebSocket API endpoint for real-time updates
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from ..services.websocket import manager
from ..models.user import User
from .deps import get_current_user
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time threat updates

    Clients can connect to receive:
    - Real-time threat notifications
    - Sensor heartbeat updates
    - System status updates
    """
    await manager.connect(websocket)

    try:
        # Send welcome message
        await manager.send_personal_message({
            'type': 'welcome',
            'message': 'Connected to Honeyman real-time feed',
            'version': '2.0.0'
        }, websocket)

        # Keep connection alive and handle client messages
        while True:
            # Receive messages from client (for potential commands)
            data = await websocket.receive_text()

            # Echo back for now (can add command handling later)
            await manager.send_personal_message({
                'type': 'echo',
                'data': data
            }, websocket)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
