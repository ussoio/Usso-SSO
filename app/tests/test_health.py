import httpx
import pytest


@pytest.mark.asyncio
async def test_health(client: httpx.AsyncClient):
    """Test the /health endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
