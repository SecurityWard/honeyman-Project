"""
WebSocket API endpoint for real-time updates
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..services.websocket import manager
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Public read-only WebSocket. Subscribers receive threat broadcasts that
    the backend pushes via Redis pub/sub. There is no client-to-server
    channel — anything the client sends is silently discarded (and capped
    in size so it can't be used as an upload vector).

    [Audit F3] Connect is refused when the global cap is hit.
    [Audit F4] No echo — used to reflect arbitrary client text, which was
               wasted CPU with no purpose.
    """
    if not await manager.connect(websocket):
        return  # capped; manager already closed the socket

    try:
        await manager.send_personal_message({
            'type': 'welcome',
            'message': 'Connected to Honeyman real-time feed',
            'version': '2.0.0',
        }, websocket)

        # Read-and-discard loop — we only consume frames so the OS doesn't
        # spam disconnects, never act on them. Tiny size cap keeps the
        # endpoint from being used as a free upload sink.
        while True:
            data = await websocket.receive_text()
            if len(data) > 1024:
                logger.warning(
                    "WebSocket client sent oversized frame (%d bytes); closing",
                    len(data),
                )
                await websocket.close(code=1009, reason="message too big")
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)
