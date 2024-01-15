from redis import Redis

from .config import CONFIG

redis: Redis = Redis.from_url(CONFIG.redis_uri)


def init_redis():
    global redis
    # redis = Redis.from_url(CONFIG.redis_uri)
