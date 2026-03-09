FROM python:3.12-slim

RUN groupadd -r meshduct && useradd -r -g meshduct meshduct

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config.yaml .

RUN chown -R meshduct:meshduct /app
USER meshduct

# No ports exposed — the relay is a client, not a server.

ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--config", "/app/config.yaml"]
