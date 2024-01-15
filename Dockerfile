FROM python:3.11-slim as fastapi-server-base

WORKDIR "/app"

COPY requirements.txt requirements.txt
RUN python -m pip install -r requirements.txt --no-cache-dir

FROM fastapi-server-base as sso-server

COPY . .

# CMD ["python", "main.py"]