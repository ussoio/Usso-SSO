FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS fast-uv

WORKDIR /app

COPY pyproject.toml pyproject.toml

RUN uv pip install --system --no-cache-dir .


FROM python:3.13-slim AS fast-server

WORKDIR /app
COPY --from=fast-uv /usr/local/lib/python3.13/site-packages \
                    /usr/local/lib/python3.13/site-packages

RUN adduser --disabled-password --gecos '' user \
    && mkdir /app/logs \
    && chown -R user:user /app/logs

USER user
COPY --chown=user:user . .

CMD [ "python", "main.py" ]
