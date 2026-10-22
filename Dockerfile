FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY infrastructure_observer/ /app/infrastructure_observer/
ENTRYPOINT ["python3", "-m", "infrastructure_observer.service"]
