import logging
import os
from typing import AsyncGenerator
from unittest.mock import patch

import debugpy
import httpx
import pytest
import pytest_asyncio
from apps.models import user, website
from beanie import init_beanie
from redis import Redis as RedisSync
from redis.asyncio.client import Redis
from server.config import Settings
from server.server import app as fastapi_app

from .constants import StaticData


@pytest.fixture(scope="session", autouse=True)
def setup_debugpy():
    if os.getenv("DEBUGPY", "False").lower() in ("true", "1", "yes"):
        debugpy.listen(("0.0.0.0", 3020))
        debugpy.wait_for_client()


@pytest.fixture(scope="session")
def mongo_client():
    from mongomock_motor import AsyncMongoMockClient

    client = AsyncMongoMockClient()
    yield client

    # from testcontainers.mongodb import MongoDbContainer
    # from motor.motor_asyncio import AsyncIOMotorClient

    # with MongoDbContainer("mongo:latest") as mongo:
    #     mongo_uri = mongo.get_connection_url()
    #     client = AsyncIOMotorClient(mongo_uri)
    #     yield client


@pytest.fixture(scope="session")
def redis_container():
    # Start Redis container
    from testcontainers.redis import RedisContainer

    with RedisContainer("redis:alpine") as redis:
        redis_host = redis.get_container_host_ip()
        redis_port = redis.get_exposed_port(6379)
        redis_url = f"redis://{redis_host}:{redis_port}"
        yield redis_url


@pytest.fixture(scope="session")
def redis_client(redis_container):
    # Patch the redis clients in your db module
    redis_sync: RedisSync = RedisSync.from_url(redis_container)
    redis: Redis = Redis.from_url(redis_container)

    with patch("server.db.redis", new=redis), patch(
        "server.db.redis_sync", new=redis_sync
    ):
        yield redis_container


# Async setup function to initialize the database with Beanie
async def init_db(mongo_client, redis_client):
    database = mongo_client.get_database("test_db")
    await init_beanie(database=database, document_models=[user.User, website.Website])


@pytest_asyncio.fixture(scope="session", autouse=True)
async def db(mongo_client, redis_client):
    Settings.config_logger()
    logging.info("Initializing database")
    await init_db(mongo_client, redis_client)
    logging.info("Database initialized")
    yield
    logging.info("Cleaning up database")


@pytest_asyncio.fixture(scope="session")
async def client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Fixture to provide an AsyncClient for FastAPI app."""

    async with httpx.AsyncClient(app=fastapi_app, base_url="http://sso.usso.io") as ac:
        yield ac


@pytest_asyncio.fixture(scope="session")
async def ufaas_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Fixture to provide an AsyncClient for FastAPI app."""

    async with httpx.AsyncClient(app=fastapi_app, base_url="http://sso.ufaas.io") as ac:
        yield ac


@pytest.fixture(scope="module")
def constants():
    return StaticData()
