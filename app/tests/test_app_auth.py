import logging
from datetime import datetime

import httpx
import pytest
import pytest_asyncio
from apps.models.website import Website
from apps.routes.app_auth import AppAuth

from .constants import StaticData


@pytest_asyncio.fixture(scope="module")
async def website(ufaas_client: httpx.AsyncClient, constants: StaticData):
    website = Website(user_uid=constants.user_id_1_1, origin="sso.ufaas.io")
    await website.save()

    website2 = Website(user_uid=constants.user_id_1_1, origin="sso.usso.io")
    await website2.save()

    yield website


@pytest.mark.asyncio
async def test_app_register(
    ufaas_client: httpx.AsyncClient, website: Website, constants: StaticData
):
    r = await ufaas_client.post(
        "/app-auth/register", json={}, headers={"x-api-key": website.api_key}
    )
    assert r.status_code == 200
    data = r.json()
    constants.app_id = data["app_id"]
    constants.app_secret = data["app_secret"]


@pytest.mark.asyncio
async def test_app_login(
    ufaas_client: httpx.AsyncClient, website: Website, constants: StaticData
):
    data = {
        "app_id": constants.app_id,
        "scopes": ["read", "write"],
        "timestamp": datetime.now().timestamp(),
        "sso_url": "sso.usso.io",
        "secret": "",
    }
    data["secret"] = AppAuth(**data).get_secret(constants.app_secret)

    r = await ufaas_client.post(
        "/app-auth/access", json=data, headers={"x-api-key": website.api_key}
    )
    logging.info(r.json())
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
