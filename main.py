from pathlib import Path

from server.server import app

if __name__ == "__main__":
    import uvicorn

    app

    module = Path(__file__).stem
    uvicorn.run(
        f"{module}:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        # access_log=False,
        workers=1,
    )
