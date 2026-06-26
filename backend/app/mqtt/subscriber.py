"""
MQTT Subscriber Service - Receives sensor data and ingests into database
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import paho.mqtt.client as mqtt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from ..core.config import settings
from ..db.base import AsyncSessionLocal
from ..models.sensor import Sensor
from ..models.threat import Threat
from ..services.redis_client import redis_client

logger = logging.getLogger(__name__)


class MQTTSubscriber:
    """MQTT subscriber for receiving sensor data"""

    def __init__(self):
        self.client: Optional[mqtt.Client] = None
        self.running = False
        self.message_queue = asyncio.Queue()
        self.worker_task = None

        # Statistics
        self.messages_received = 0
        self.threats_ingested = 0
        self.heartbeats_received = 0
        self.errors = 0

    def start(self):
        """Start MQTT subscriber"""
        logger.info("Starting MQTT subscriber service")

        # Create MQTT client
        self.client = mqtt.Client(client_id="honeyman-dashboard", clean_session=False)

        # Set callbacks
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

        # Configure authentication
        if settings.MQTT_BROKER_USERNAME and settings.MQTT_BROKER_PASSWORD:
            self.client.username_pw_set(
                settings.MQTT_BROKER_USERNAME,
                settings.MQTT_BROKER_PASSWORD
            )

        # Configure TLS
        if settings.MQTT_USE_TLS:
            if settings.MQTT_CA_CERT:
                self.client.tls_set(ca_certs=settings.MQTT_CA_CERT)
            else:
                self.client.tls_set()

        # Connect to broker
        try:
            self.client.connect(
                settings.MQTT_BROKER_HOST,
                settings.MQTT_BROKER_PORT,
                keepalive=60
            )

            # Start network loop in background thread
            self.client.loop_start()

            self.running = True
            logger.info(f"Connected to MQTT broker at {settings.MQTT_BROKER_HOST}:{settings.MQTT_BROKER_PORT}")

        except Exception as e:
            logger.error(f"Failed to connect to MQTT broker: {e}")
            raise

    async def start_worker(self):
        """Start async worker to process messages"""
        logger.info("Starting MQTT message worker")
        self.worker_task = asyncio.create_task(self._process_messages())

    def stop(self):
        """Stop MQTT subscriber"""
        logger.info("Stopping MQTT subscriber service")
        self.running = False

        if self.client:
            self.client.loop_stop()
            self.client.disconnect()

        if self.worker_task:
            self.worker_task.cancel()

    def _on_connect(self, client, userdata, flags, rc):
        """Callback for when connected to MQTT broker"""
        if rc == 0:
            logger.info("Successfully connected to MQTT broker")

            # Subscribe to topics
            topics = [
                (settings.MQTT_TOPIC_THREATS, 1),
                (settings.MQTT_TOPIC_HEARTBEAT, 1),
                (settings.MQTT_TOPIC_CONTROL, 1)
            ]

            for topic, qos in topics:
                client.subscribe(topic, qos)
                logger.info(f"Subscribed to topic: {topic}")

        else:
            logger.error(f"Failed to connect to MQTT broker: {rc}")

    def _on_message(self, client, userdata, msg):
        """Callback for when message received"""
        try:
            self.messages_received += 1

            # Parse message
            payload = json.loads(msg.payload.decode('utf-8'))

            # Add to queue for async processing
            asyncio.run_coroutine_threadsafe(
                self.message_queue.put((msg.topic, payload)),
                asyncio.get_event_loop()
            )

        except Exception as e:
            logger.error(f"Error parsing MQTT message: {e}")
            self.errors += 1

    def _on_disconnect(self, client, userdata, rc):
        """Callback for when disconnected from broker"""
        if rc != 0:
            logger.warning(f"Unexpected disconnect from MQTT broker: {rc}")
            logger.info("Attempting to reconnect...")
        else:
            logger.info("Disconnected from MQTT broker")

    async def _process_messages(self):
        """Process messages from queue"""
        logger.info("MQTT message processor started")

        while self.running:
            try:
                # Get message from queue (with timeout)
                try:
                    topic, payload = await asyncio.wait_for(
                        self.message_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                # Route message based on topic
                if "/threats" in topic:
                    await self._handle_threat(topic, payload)
                elif "/heartbeat" in topic:
                    await self._handle_heartbeat(topic, payload)
                elif "/control/" in topic:
                    await self._handle_control(topic, payload)
                else:
                    logger.warning(f"Unknown topic: {topic}")

            except Exception as e:
                logger.error(f"Error processing MQTT message: {e}", exc_info=True)
                self.errors += 1

        logger.info("MQTT message processor stopped")

    async def _handle_threat(self, topic: str, payload: Dict[str, Any]):
        """Handle threat message"""
        try:
            # Extract sensor_id from topic
            sensor_id = self._extract_sensor_id(topic)

            if not sensor_id:
                logger.error(f"Could not extract sensor_id from topic: {topic}")
                return

            # Create threat in database
            async with AsyncSessionLocal() as db:
                threat = Threat(
                    timestamp=datetime.fromisoformat(payload['timestamp']) if 'timestamp' in payload else datetime.utcnow(),
                    sensor_id=sensor_id,
                    threat_type=payload.get('threat_type'),
                    detector_type=payload.get('detector_type'),
                    severity=payload.get('severity'),
                    device_name=payload.get('device_name'),
                    device_mac=payload.get('device_mac'),
                    device_ip=payload.get('device_ip'),
                    src_host=payload.get('src_host'),
                    src_port=payload.get('src_port'),
                    dst_host=payload.get('dst_host'),
                    dst_port=payload.get('dst_port'),
                    latitude=payload.get('latitude'),
                    longitude=payload.get('longitude'),
                    city=payload.get('city'),
                    country=payload.get('country'),
                    matched_rules=payload.get('matched_rules', []),
                    confidence=payload.get('confidence'),
                    threat_score=payload.get('threat_score'),
                    raw_event=payload.get('raw_event'),
                    mitre_tactics=payload.get('mitre_tactics', []),
                    mitre_techniques=payload.get('mitre_techniques', [])
                )

                db.add(threat)
                await db.commit()
                await db.refresh(threat)

                # Update sensor statistics
                await self._update_sensor_stats(db, sensor_id)

                self.threats_ingested += 1
                logger.info(f"Threat ingested: {threat.threat_type} from {sensor_id}")

                # Publish to Redis for real-time updates
                await self._publish_threat_to_redis(threat)

        except Exception as e:
            logger.error(f"Error handling threat: {e}", exc_info=True)
            self.errors += 1

    async def _handle_heartbeat(self, topic: str, payload: Dict[str, Any]):
        """Handle heartbeat message"""
        try:
            sensor_id = self._extract_sensor_id(topic)

            if not sensor_id:
                logger.error(f"Could not extract sensor_id from topic: {topic}")
                return

            async with AsyncSessionLocal() as db:
                # Update sensor heartbeat
                result = await db.execute(
                    select(Sensor).where(Sensor.sensor_id == sensor_id)
                )
                sensor = result.scalar_one_or_none()

                if sensor:
                    sensor.last_heartbeat = datetime.utcnow()
                    sensor.is_online = payload.get('is_online', True)

                    # Update location if provided
                    if 'location' in payload:
                        location = payload['location']
                        sensor.latitude = location.get('latitude')
                        sensor.longitude = location.get('longitude')
                        sensor.location_method = location.get('method')
                        sensor.location_accuracy = location.get('accuracy')

                    # Update enabled detectors if provided
                    if 'enabled_detectors' in payload:
                        sensor.enabled_detectors = payload['enabled_detectors']

                    await db.commit()

                    self.heartbeats_received += 1
                    logger.debug(f"Heartbeat received from {sensor_id}")

                else:
                    logger.warning(f"Heartbeat from unknown sensor: {sensor_id}")

        except Exception as e:
            logger.error(f"Error handling heartbeat: {e}", exc_info=True)
            self.errors += 1

    async def _handle_control(self, topic: str, payload: Dict[str, Any]):
        """Handle control message (rule updates, configuration changes)"""
        try:
            logger.info(f"Control message received: {topic}")
            # TODO: Implement control message handling
            # - Rule updates
            # - Configuration changes
            # - Sensor commands

        except Exception as e:
            logger.error(f"Error handling control message: {e}", exc_info=True)
            self.errors += 1

    async def _update_sensor_stats(self, db: AsyncSession, sensor_id: str):
        """Update sensor threat statistics"""
        try:
            # Get threat count for last 24 hours
            from sqlalchemy import func
            from datetime import timedelta

            now = datetime.utcnow()
            last_24h = now - timedelta(hours=24)

            result = await db.execute(
                select(func.count()).where(
                    Threat.sensor_id == sensor_id,
                    Threat.timestamp >= last_24h
                )
            )
            threats_24h = result.scalar()

            # Update sensor
            await db.execute(
                update(Sensor).where(Sensor.sensor_id == sensor_id).values(
                    threats_last_24h=threats_24h,
                    total_threats_detected=Sensor.total_threats_detected + 1
                )
            )

        except Exception as e:
            logger.error(f"Error updating sensor stats: {e}")

    async def _publish_threat_to_redis(self, threat: Threat):
        """Publish threat to Redis for real-time updates"""
        try:
            threat_data = {
                'id': str(threat.id),
                'timestamp': threat.timestamp.isoformat(),
                'sensor_id': threat.sensor_id,
                'threat_type': threat.threat_type,
                'severity': threat.severity,
                'detector_type': threat.detector_type
            }

            await redis_client.publish('threats:realtime', json.dumps(threat_data))

        except Exception as e:
            logger.error(f"Error publishing to Redis: {e}")

    def _extract_sensor_id(self, topic: str) -> Optional[str]:
        """Extract sensor_id from MQTT topic"""
        # Topic format: honeyman/sensors/{sensor_id}/threats
        parts = topic.split('/')
        if len(parts) >= 3 and parts[0] == 'honeyman' and parts[1] == 'sensors':
            return parts[2]
        return None

    def get_stats(self) -> Dict[str, int]:
        """Get subscriber statistics"""
        return {
            'messages_received': self.messages_received,
            'threats_ingested': self.threats_ingested,
            'heartbeats_received': self.heartbeats_received,
            'errors': self.errors,
            'queue_size': self.message_queue.qsize()
        }


# Global instance
mqtt_subscriber = MQTTSubscriber()
