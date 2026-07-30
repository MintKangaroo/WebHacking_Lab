FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY backend/pyproject.toml README.md ./
COPY backend/webhacking_lab ./webhacking_lab
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.12-slim AS test

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY backend/pyproject.toml ./
RUN mkdir -p webhacking_lab \
    && touch webhacking_lab/__init__.py \
    && python -m pip install -e ".[dev]"
COPY backend/webhacking_lab ./webhacking_lab
COPY backend/tests ./tests
RUN ruff check . \
    && ruff format --check . \
    && mypy webhacking_lab \
    && pytest --cov=webhacking_lab --cov-report=term-missing

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/webhacking/.local/bin:${PATH}"

RUN groupadd --system --gid 10001 webhacking \
    && useradd --system --uid 10001 --gid webhacking --create-home webhacking \
    && mkdir -p /app/data \
    && chown -R webhacking:webhacking /app

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels webhacking-lab \
    && rm -rf /wheels

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "webhacking_lab.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
