FROM python:3.12-slim AS fast-base

WORKDIR /app

COPY requirements.txt requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt 
    # -i https://mirror-pypi.runflare.com/simple

RUN adduser --disabled-password --gecos '' user && mkdir /app/logs && chown -R user:user /app/logs

FROM fast-base AS fast-server

USER user
COPY --chown=user:user . .

# CMD ["python", "-m" ,"debugpy", "--listen", "0.0.0.0:3000", "-m", "app"]
CMD [ "python", "main.py" ]