"""
WebSocket service for real-time threat updates
"""

import asyncio
import json
import logging
from typing import Set, Dict, Any
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime

from .redis_client import redis_client

logger = logging.getLogger(__name__)


# Hard cap on simultaneous WebSocket clients. We don't have an ops case for
# more than a few hundred concurrent dashboards open at once; this lid stops
# a single attacker from exhausting file descriptors via tens of thousands
# of WS connects. [Audit F3]
MAX_CONNECTIONS = 500


class ConnectionManager:
    """Manages WebSocket connections"""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.subscriber_task = None
        self.running = False

    async def connect(self, websocket: WebSocket) -> bool:
        """Accept a new WebSocket connection if we're under the cap.

        Returns True on accept, False on refusal (caller should bail out of
        any further interaction with the socket — we've already closed it).
        """
        if len(self.active_connections) >= MAX_CONNECTIONS:
            # 1013 = "try again later". Spec-correct for "I have capacity
            # but right now I'm full". Browsers handle it fine.
            logger.warning(
                "Refusing WebSocket connect: at cap (%d/%d)",
                len(self.active_connections),
                MAX_CONNECTIONS,
            )
            try:
                await websocket.close(code=1013, reason="Server at connection cap")
            except Exception:
                # Already disconnected; nothing to clean up.
                pass
            return False

        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(
            "WebSocket client connected. Total connections: %d",
            len(self.active_connections),
        )
        return True

    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        """Send message to specific client"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message to client: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        disconnected = set()

        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")
                disconnected.add(connection)

        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)

    async def start_redis_subscriber(self):
        """Start Redis subscriber to forward messages to WebSocket clients"""
        logger.info("Starting Redis subscriber for WebSocket broadcast")
        self.running = True

        try:
            # Subscribe to Redis channels
            pubsub = await redis_client.subscribe('threats:realtime')

            if not pubsub:
                logger.error("Failed to subscribe to Redis channels")
                return

            # Listen for messages
            while self.running:
                try:
                    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)

                    if message and message['type'] == 'message':
                        # Parse message
                        data = json.loads(message['data'])

                        # Add event type
                        event = {
                            'type': 'threat',
                            'data': data,
                            'timestamp': datetime.utcnow().isoformat()
                        }

                        # Broadcast to all WebSocket clients
                        await self.broadcast(event)

                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing Redis message: {e}")

        except Exception as e:
            logger.error(f"Redis subscriber error: {e}", exc_info=True)
        finally:
            if pubsub:
                await pubsub.unsubscribe()
                await pubsub.close()

        logger.info("Redis subscriber stopped")

    def stop_redis_subscriber(self):
        """Stop Redis subscriber"""
        self.running = False
        if self.subscriber_task:
            self.subscriber_task.cancel()

    async def send_heartbeat(self):
        """Send periodic heartbeat to keep connections alive"""
        while True:
            try:
                heartbeat = {
                    'type': 'heartbeat',
                    'timestamp': datetime.utcnow().isoformat(),
                    'connections': len(self.active_connections)
                }

                await self.broadcast(heartbeat)
                await asyncio.sleep(30)  # Every 30 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")


# Global instance
manager = ConnectionManager()
