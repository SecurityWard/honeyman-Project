"""
Redis client for caching and pub/sub
"""

import redis.asyncio as aioredis
import json
import logging
from typing import Optional, Any
from ..core.config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    """Async Redis client for caching and pub/sub"""

    def __init__(self):
        self.redis: Optional[aioredis.Redis] = None
        self.pubsub: Optional[aioredis.client.PubSub] = None

    async def connect(self):
        """Connect to Redis"""
        try:
            self.redis = await aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )

            # Test connection
            await self.redis.ping()
            logger.info(f"Connected to Redis at {settings.REDIS_URL}")

        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis:
            await self.redis.close()
            logger.info("Disconnected from Redis")

    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis"""
        try:
            return await self.redis.get(key)
        except Exception as e:
            logger.error(f"Redis GET error: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in Redis with optional TTL"""
        try:
            if ttl:
                await self.redis.setex(key, ttl, value)
            else:
                await self.redis.set(key, value)
        except Exception as e:
            logger.error(f"Redis SET error: {e}")

    async def delete(self, key: str):
        """Delete key from Redis"""
        try:
            await self.redis.delete(key)
        except Exception as e:
            logger.error(f"Redis DELETE error: {e}")

    async def publish(self, channel: str, message: str):
        """Publish message to channel"""
        try:
            await self.redis.publish(channel, message)
        except Exception as e:
            logger.error(f"Redis PUBLISH error: {e}")

    async def subscribe(self, *channels: str):
        """Subscribe to channels"""
        try:
            self.pubsub = self.redis.pubsub()
            await self.pubsub.subscribe(*channels)
            return self.pubsub
        except Exception as e:
            logger.error(f"Redis SUBSCRIBE error: {e}")
            return None

    async def get_json(self, key: str) -> Optional[dict]:
        """Get JSON value from Redis"""
        value = await self.get(key)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON from Redis key: {key}")
        return None

    async def set_json(self, key: str, value: dict, ttl: Optional[int] = None):
        """Set JSON value in Redis"""
        await self.set(key, json.dumps(value), ttl)

    async def cache_sensor_stats(self, sensor_id: str, stats: dict, ttl: int = 300):
        """Cache sensor statistics"""
        key = f"sensor_stats:{sensor_id}"
        await self.set_json(key, stats, ttl)

    async def get_cached_sensor_stats(self, sensor_id: str) -> Optional[dict]:
        """Get cached sensor statistics"""
        key = f"sensor_stats:{sensor_id}"
        return await self.get_json(key)

    async def invalidate_sensor_cache(self, sensor_id: str):
        """Invalidate sensor cache"""
        key = f"sensor_stats:{sensor_id}"
        await self.delete(key)


# Global instance
redis_client = RedisClient()
