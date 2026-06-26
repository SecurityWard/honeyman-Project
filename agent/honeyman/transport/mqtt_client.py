#!/usr/bin/env python3
"""MQTT Client - Primary transport protocol"""

import json
import logging
import asyncio
from typing import Dict, Any
import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)


class MQTTClient:
    """
    MQTT client for sensor communication

    Features:
    - TLS 1.3 encryption
    - QoS 1 (at least once delivery)
    - Automatic reconnection
    - Topic-based routing
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize MQTT client

        Args:
            config: MQTT configuration
        """
        self.broker = config.get('broker', 'localhost')
        self.port = config.get('port', 8883)
        self.username = config.get('username')
        self.password = config.get('password')
        self.sensor_id = config.get('sensor_id', 'unknown')
        self.use_tls = config.get('use_tls', True)
        self.qos = config.get('qos', 1)

        self.client = mqtt.Client(client_id=f"honeyman-{self.sensor_id}")
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

        # Set credentials
        if self.username and self.password:
            self.client.username_pw_set(self.username, self.password)

        # Configure TLS
        if self.use_tls:
            self.client.tls_set()

        self.connected = False
        self.reconnect_event = asyncio.Event()

    def _on_connect(self, client, userdata, flags, rc):
        """Handle connection callback"""
        if rc == 0:
            self.connected = True
            self.reconnect_event.set()
            logger.info(f"MQTT connected to {self.broker}:{self.port}")

            # Subscribe to command topics
            topics = [
                f"honeyman/dashboard/commands/{self.sensor_id}",
                f"honeyman/dashboard/updates/{self.sensor_id}"
            ]

            for topic in topics:
                client.subscribe(topic, qos=self.qos)
                logger.debug(f"Subscribed to {topic}")
        else:
            self.connected = False
            logger.error(f"MQTT connection failed with code {rc}")

    def _on_disconnect(self, client, userdata, rc):
        """Handle disconnection callback"""
        self.connected = False
        self.reconnect_event.clear()

        if rc != 0:
            logger.warning(f"MQTT disconnected unexpectedly (code: {rc})")
        else:
            logger.info("MQTT disconnected")

    def _on_message(self, client, userdata, msg):
        """Handle incoming messages"""
        try:
            payload = json.loads(msg.payload.decode())
            logger.info(f"Received message on {msg.topic}: {payload.get('type', 'unknown')}")

            # Handle different message types
            if 'rule_update' in msg.topic or payload.get('type') == 'rule_update':
                self._handle_rule_update(payload)
            elif 'command' in msg.topic:
                self._handle_command(payload)

        except Exception as e:
            logger.error(f"Error handling MQTT message: {e}")

    def _handle_rule_update(self, payload: Dict[str, Any]):
        """Handle rule update messages"""
        logger.info("Received rule update notification")
        # TODO: Trigger rule reload in agent
        pass

    def _handle_command(self, payload: Dict[str, Any]):
        """Handle command messages"""
        command = payload.get('command')
        logger.info(f"Received command: {command}")
        # TODO: Implement command handling
        pass

    async def connect(self):
        """Establish MQTT connection"""
        try:
            self.client.connect_async(self.broker, self.port, keepalive=60)
            self.client.loop_start()

            # Wait for connection (with timeout)
            await asyncio.wait_for(self.reconnect_event.wait(), timeout=10.0)

            return True

        except asyncio.TimeoutError:
            logger.error("MQTT connection timeout")
            return False
        except Exception as e:
            logger.error(f"MQTT connection error: {e}")
            return False

    async def send(self, data: Dict[str, Any], topic: str = 'threats') -> bool:
        """
        Publish data to MQTT topic

        Args:
            data: Data dictionary
            topic: Topic type ('threats', 'heartbeat', 'registration')

        Returns:
            True if published successfully
        """
        if not self.connected:
            logger.warning("MQTT not connected, cannot send")
            return False

        try:
            # Build full topic path
            if topic == 'threats':
                full_topic = f"honeyman/sensors/{self.sensor_id}/threats"
            elif topic == 'heartbeat':
                full_topic = f"honeyman/sensors/{self.sensor_id}/heartbeat"
            elif topic == 'registration':
                full_topic = f"honeyman/sensors/{self.sensor_id}/status"
            else:
                full_topic = f"honeyman/sensors/{self.sensor_id}/{topic}"

            # Serialize payload
            payload = json.dumps(data)

            # Publish
            result = self.client.publish(full_topic, payload, qos=self.qos)

            # Wait for publish to complete
            await asyncio.get_event_loop().run_in_executor(
                None, result.wait_for_publish, 5.0
            )

            if result.is_published():
                logger.debug(f"Published to {full_topic}")
                return True
            else:
                logger.warning("MQTT publish failed")
                return False

        except Exception as e:
            logger.error(f"MQTT publish error: {e}")
            return False

    async def disconnect(self):
        """Disconnect MQTT client"""
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
        self.connected = False
