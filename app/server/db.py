from fastapi_mongo_base.core import db

redis_sync, redis = db.init_redis()
